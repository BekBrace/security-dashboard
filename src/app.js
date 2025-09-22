const express = require('express'); // Import Express.js framework for node.js.
const path = require('path'); // Core module to work with file paths
const sslChecker = require('ssl-checker'); // Library to check SSL certificate info
const dns = require('dns'); // Built-in DNS module for resolving domains
const fetch = require('node-fetch'); // Library to make HTTP requests

const app = express(); // Create Express app instance
const port = 3000; // Define the port number

// Middleware setup
app.use(express.json()); // Parse incoming JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded form data
app.use(express.static('public')); // Serve static files from the 'public' directory
app.set('view engine', 'ejs'); // Set EJS as the templating/view engine
app.set('views', path.join(__dirname, 'views')); // Set directory for EJS views

// Home route
app.get('/', (req, res) => {
    res.render('index'); // Render the 'index.ejs' view
});

// SSL Certificate Checker endpoint
app.post('/api/check-ssl', async (req, res) => {
    try {
        const { domain } = req.body; // Extract domain from request body
        const result = await sslChecker(domain); // Use ssl-checker to get certificate info
        res.json(result); // Send result back as JSON
    } catch (error) {
        res.status(500).json({ error: error.message }); // Send error message if it fails
    }
});

// DNS Record Analyzer endpoint
app.post('/api/check-dns', async (req, res) => {
    try {
        const { domain } = req.body; // Extract domain from request body
        const records = await new Promise((resolve, reject) => {
            dns.resolveAny(domain, (err, records) => { // Perform DNS lookup
                if (err) reject(err); // Reject promise if error
                else resolve(records); // Resolve with DNS records
            });
        });
        res.json(records); // Send records back as JSON
    } catch (error) {
        res.status(500).json({ error: error.message }); // Error handler
    }
});

// HTTP Headers Security Check endpoint
app.post('/api/check-headers', async(req, res) =>{
    try{
        const {url} = req.body;
        const response = await fetch(url);
        const headers = response.headers.raw();
        const securityHeaders = {
            'Strict-Transport-Security' : headers['strict-transport-security'] || null,
            'Strict-Security-Policy' : headers['strict-security-policy'] || null,
            'X-Frame-Options' : headers['x-frame-options'] || null,
            'X-Content-Type-Options' : headers['x-content-type-options'] || null,
            'X-XSS-Protection' : headers['x-xss-protection'] || null,
        };
        res.json(securityHeaders);
    } catch(error){
        res.status(500).json({error: error.message});
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Security Dashboard running at http://localhost:${port}`); // Server startup message
});
