const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const db = new sqlite3.Database('./data/database.sqlite');

app.use(express.json());
app.use(express.static('public'));

db.serialize(() => {
    // New Table for Sessions
    db.run("CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)");
    // Items now linked to a session
    db.run("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, text TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS votes (item_id INTEGER, voter_id TEXT, value INTEGER, PRIMARY KEY(item_id, voter_id))");
});

// --- SESSION ROUTES ---
app.get('/api/sessions', (req, res) => {
    db.all("SELECT * FROM sessions", [], (err, rows) => res.json(rows));
});

app.post('/api/sessions', (req, res) => {
    db.run("INSERT INTO sessions (name) VALUES (?)", [req.body.name], function(err) {
        if (err) return res.status(400).json({error: "Session exists"});
        res.json({ id: this.lastID });
    });
});

// --- ITEM & VOTE ROUTES ---
app.get('/api/sessions/:id/items', (req, res) => {
    const voter_id = req.query.voter_id;
    const query = `
        SELECT i.id, i.text, 
        (SELECT SUM(value) FROM votes WHERE item_id = i.id) as score,
        (SELECT value FROM votes WHERE item_id = i.id AND voter_id = ?) as user_vote
        FROM items i WHERE i.session_id = ? 
        ORDER BY score DESC`;
    db.all(query, [voter_id, req.params.id], (err, rows) => res.json(rows));
});

app.post('/api/items', (req, res) => {
    db.run("INSERT INTO items (session_id, text) VALUES (?, ?)", [req.body.session_id, req.body.text], res.sendStatus(200));
});

// Logic for +1, -1, and Neutral
app.post('/api/vote', (req, res) => {
    const { item_id, voter_id, value } = req.body;
    
    // Check existing vote
    db.get("SELECT value FROM votes WHERE item_id = ? AND voter_id = ?", [item_id, voter_id], (err, row) => {
        if (row && row.value === value) {
            // If clicking the same button again, remove the vote (Neutral)
            db.run("DELETE FROM votes WHERE item_id = ? AND voter_id = ?", [item_id, voter_id], () => res.sendStatus(200));
        } else {
            // Otherwise, Insert or Update
            db.run("INSERT INTO votes (item_id, voter_id, value) VALUES (?, ?, ?) ON CONFLICT(item_id, voter_id) DO UPDATE SET value = ?", 
            [item_id, voter_id, value, value], () => res.sendStatus(200));
        }
    });
});

app.listen(3000, () => console.log('Server: http://localhost:3000'));
