#!/usr/bin/env node
// Minifies public/index.html → dist/index.html
const { minify } = require('html-minifier-terser');
const fs = require('fs');
const path = require('path');

const src  = path.join(__dirname, 'public', 'index.html');
const dest = path.join(__dirname, 'dist',   'index.html');

fs.mkdirSync(path.dirname(dest), { recursive: true });

const html = fs.readFileSync(src, 'utf8');

minify(html, {
    collapseWhitespace: true,
    removeComments: true,
    minifyCSS: true,
    minifyJS: true,
    removeAttributeQuotes: true,
    removeRedundantAttributes: true,
    useShortDoctype: true,
}).then(minified => {
    fs.writeFileSync(dest, minified);
    const pct = (100 - (minified.length / html.length) * 100).toFixed(1);
    console.log(`Minified index.html: ${html.length} → ${minified.length} bytes (${pct}% smaller)`);
});

