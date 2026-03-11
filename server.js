const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcrypt');
const crypto   = require('crypto');
const sqlite3  = require('sqlite3').verbose();
const fs       = require('fs');
const path     = require('path');

const app = express();
const db  = new sqlite3.Database('./data/database.sqlite');

// Serve minified dist/ in production, raw public/ in development
const staticDir = fs.existsSync(path.join(__dirname, 'dist')) ? 'dist' : 'public';

// ─── Database setup ─────────────────────────────────────────────────────────────
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT NOT NULL UNIQUE,
        password     TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name     TEXT UNIQUE,
        hash     TEXT UNIQUE,
        owner_id INTEGER REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS session_permissions (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id           INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        user_id              INTEGER REFERENCES users(id) ON DELETE CASCADE,
        can_view             INTEGER DEFAULT 1,
        can_add_items        INTEGER DEFAULT 0,
        can_vote             INTEGER DEFAULT 0,
        can_remove_items     INTEGER DEFAULT 0,
        can_remove_session   INTEGER DEFAULT 0,
        can_edit_permissions INTEGER DEFAULT 0,
        UNIQUE(session_id, user_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS items (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        text       TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS votes (
        item_id  INTEGER,
        voter_id TEXT,
        value    INTEGER,
        PRIMARY KEY(item_id, voter_id)
    )`);
});

// ─── Middleware ──────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// Attach user to req if logged in
app.use((req, res, next) => {
    if (!req.session.userId) return next();
    db.get('SELECT id, username FROM users WHERE id = ?', [req.session.userId], (err, row) => {
        req.user = row || null;
        next();
    });
});

// ─── Auth routes ─────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username?.trim() || !password) return res.status(400).json({ error: 'Username and password required' });
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username.trim(), hash], function(err) {
        if (err) return res.status(400).json({ error: 'Username already taken' });
        req.session.userId = this.lastID;
        res.json({ id: this.lastID, username: username.trim() });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username?.trim() || !password) return res.status(400).json({ error: 'Username and password required' });
    db.get('SELECT * FROM users WHERE username = ?', [username.trim()], async (err, user) => {
        if (!user) return res.status(401).json({ error: 'Invalid username or password' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid username or password' });
        req.session.userId = user.id;
        res.json({ id: user.id, username: user.username });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => res.sendStatus(200));
});

app.get('/api/me', (req, res) => res.json(req.user || null));

// ─── Permission helpers ──────────────────────────────────────────────────────────
function loadSession(req, res, next) {
    db.get('SELECT * FROM sessions WHERE hash = ?', [req.params.hash], (err, row) => {
        if (err)  return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Session not found' });
        req.votingSession = row;
        next();
    });
}

function loadSessionByItem(req, res, next) {
    const itemId = req.params.id || req.body?.item_id;
    db.get('SELECT s.* FROM sessions s JOIN items i ON i.session_id = s.id WHERE i.id = ?',
        [itemId], (err, row) => {
            if (err)  return res.status(500).json({ error: err.message });
            if (!row) return res.status(404).json({ error: 'Item not found' });
            req.votingSession = row;
            next();
        });
}

function isOwner(req) {
    const vs = req.votingSession;
    if (req.user && vs.owner_id === req.user.id) return true;
    if (!req.user && req.session.ownedSessions?.includes(vs.id)) return true;
    return false;
}

function requirePermission(flag) {
    return (req, res, next) => {
        if (isOwner(req)) return next();
        const userId = req.user?.id ?? null;
        db.get(
            `SELECT * FROM session_permissions
             WHERE session_id = ? AND (user_id = ? OR user_id IS NULL)
             ORDER BY CASE WHEN user_id IS NULL THEN 1 ELSE 0 END LIMIT 1`,
            [req.votingSession.id, userId],
            (err, perm) => {
                if (err)                  return res.status(500).json({ error: err.message });
                if (!perm || !perm[flag]) return res.status(403).json({ error: 'Forbidden' });
                req.userPerm = perm;
                next();
            }
        );
    };
}

// ─── Sessions ────────────────────────────────────────────────────────────────────
app.get('/api/sessions/by-hash/:hash', loadSession, requirePermission('can_view'), (req, res) => {
    res.json(req.votingSession);
});

app.post('/api/sessions', (req, res) => {
    const hash    = crypto.randomBytes(6).toString('hex');
    const ownerId = req.user?.id ?? null;
    db.run('INSERT INTO sessions (name, hash, owner_id) VALUES (?, ?, ?)',
        [req.body.name, hash, ownerId],
        function(err) {
            if (err) return res.status(400).json({ error: 'Session name already exists' });
            const sessionId = this.lastID;
            if (!req.user) {
                if (!req.session.ownedSessions) req.session.ownedSessions = [];
                req.session.ownedSessions.push(sessionId);
            }
            // Default: anyone with link can view, vote, add items
            db.run(
                `INSERT INTO session_permissions
                 (session_id, user_id, can_view, can_add_items, can_vote, can_remove_items, can_remove_session, can_edit_permissions)
                 VALUES (?, NULL, 1, 1, 1, 0, 0, 0)`,
                [sessionId], () => res.json({ id: sessionId, hash })
            );
        }
    );
});

app.delete('/api/sessions/:hash', loadSession, requirePermission('can_remove_session'), (req, res) => {
    const id = req.votingSession.id;
    db.serialize(() => {
        db.run('DELETE FROM votes WHERE item_id IN (SELECT id FROM items WHERE session_id = ?)', [id]);
        db.run('DELETE FROM items WHERE session_id = ?', [id]);
        db.run('DELETE FROM session_permissions WHERE session_id = ?', [id]);
        db.run('DELETE FROM sessions WHERE id = ?', [id], () => res.sendStatus(200));
    });
});

// ─── Permissions ─────────────────────────────────────────────────────────────────
app.get('/api/sessions/:hash/my-permissions', loadSession, (req, res) => {
    if (isOwner(req)) {
        return res.json({ can_view:1, can_add_items:1, can_vote:1, can_remove_items:1,
            can_remove_session:1, can_edit_permissions:1, is_owner:true });
    }
    const userId = req.user?.id ?? null;
    db.get(
        `SELECT * FROM session_permissions
         WHERE session_id = ? AND (user_id = ? OR user_id IS NULL)
         ORDER BY CASE WHEN user_id IS NULL THEN 1 ELSE 0 END LIMIT 1`,
        [req.votingSession.id, userId],
        (err, perm) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(perm ? { ...perm, is_owner: false }
                : { can_view:0, can_add_items:0, can_vote:0, can_remove_items:0,
                    can_remove_session:0, can_edit_permissions:0, is_owner:false });
        }
    );
});

app.get('/api/sessions/:hash/permissions', loadSession, requirePermission('can_edit_permissions'), (req, res) => {
    db.all(
        `SELECT sp.*, u.username
         FROM session_permissions sp
         LEFT JOIN users u ON u.id = sp.user_id
         WHERE sp.session_id = ?
         ORDER BY CASE WHEN sp.user_id IS NULL THEN 0 ELSE 1 END, u.username`,
        [req.votingSession.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.put('/api/sessions/:hash/permissions', loadSession, requirePermission('can_edit_permissions'), (req, res) => {
    const rows = req.body;
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'Expected array' });
    const stmt = db.prepare(
        `INSERT INTO session_permissions
         (session_id, user_id, can_view, can_add_items, can_vote, can_remove_items, can_remove_session, can_edit_permissions)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(session_id, user_id) DO UPDATE SET
             can_view=excluded.can_view, can_add_items=excluded.can_add_items,
             can_vote=excluded.can_vote, can_remove_items=excluded.can_remove_items,
             can_remove_session=excluded.can_remove_session,
             can_edit_permissions=excluded.can_edit_permissions`
    );
    rows.forEach(r => stmt.run([
        req.votingSession.id, r.user_id ?? null,
        r.can_view?1:0, r.can_add_items?1:0, r.can_vote?1:0,
        r.can_remove_items?1:0, r.can_remove_session?1:0, r.can_edit_permissions?1:0
    ]));
    stmt.finalize(() => res.sendStatus(200));
});

app.delete('/api/sessions/:hash/permissions/:userId', loadSession, requirePermission('can_edit_permissions'), (req, res) => {
    const uid = req.params.userId === 'public' ? null : parseInt(req.params.userId);
    db.run('DELETE FROM session_permissions WHERE session_id = ? AND user_id IS ?',
        [req.votingSession.id, uid], () => res.sendStatus(200));
});

// Look up user by username (for adding to permissions)
app.get('/api/users/by-username', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const username = req.query.username?.trim();
    if (!username) return res.status(400).json({ error: 'Missing username' });
    db.get('SELECT id, username FROM users WHERE username = ?', [username], (err, row) => {
        if (err)  return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json(row);
    });
});

// ─── Items ───────────────────────────────────────────────────────────────────────
app.get('/api/sessions/:hash/items', loadSession, requirePermission('can_view'), (req, res) => {
    const voter_id = req.user ? String(req.user.id) : req.query.voter_id;
    const query = `
        SELECT i.id, i.text,
        (SELECT SUM(value) FROM votes WHERE item_id = i.id) as score,
        (SELECT value FROM votes WHERE item_id = i.id AND voter_id = ?) as user_vote
        FROM items i WHERE i.session_id = ?
        ORDER BY score DESC`;
    db.all(query, [voter_id, req.votingSession.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/items', (req, res, next) => {
    db.get('SELECT * FROM sessions WHERE hash = ?', [req.body.session_hash], (err, row) => {
        if (err)  return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Session not found' });
        req.votingSession = row;
        next();
    });
}, requirePermission('can_add_items'), (req, res) => {
    db.run('INSERT INTO items (session_id, text) VALUES (?, ?)',
        [req.votingSession.id, req.body.text], () => res.sendStatus(200));
});

app.delete('/api/items/:id', loadSessionByItem, requirePermission('can_remove_items'), (req, res) => {
    db.serialize(() => {
        db.run('DELETE FROM votes WHERE item_id = ?', [req.params.id]);
        db.run('DELETE FROM items WHERE id = ?', [req.params.id], () => res.sendStatus(200));
    });
});

// ─── Votes ───────────────────────────────────────────────────────────────────────
app.post('/api/vote', (req, res, next) => {
    db.get('SELECT s.* FROM sessions s JOIN items i ON i.session_id = s.id WHERE i.id = ?',
        [req.body.item_id], (err, row) => {
            if (err)  return res.status(500).json({ error: err.message });
            if (!row) return res.status(404).json({ error: 'Item not found' });
            req.votingSession = row;
            next();
        });
}, requirePermission('can_vote'), (req, res) => {
    const { item_id, value } = req.body;
    const voter_id = req.user ? String(req.user.id) : req.body.voter_id;
    db.get('SELECT value FROM votes WHERE item_id = ? AND voter_id = ?', [item_id, voter_id], (err, row) => {
        if (row && row.value === value) {
            db.run('DELETE FROM votes WHERE item_id = ? AND voter_id = ?', [item_id, voter_id], () => res.sendStatus(200));
        } else {
            db.run(
                `INSERT INTO votes (item_id, voter_id, value) VALUES (?, ?, ?)
                 ON CONFLICT(item_id, voter_id) DO UPDATE SET value = ?`,
                [item_id, voter_id, value, value], () => res.sendStatus(200));
        }
    });
});

app.listen(3000, () => console.log('Server: http://localhost:3000'));
