require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const uploadRoutes = require('./upload');
const spotifyRoutes = require('./spotify');
const probeRoutes = require('./probe');
const speedtestRoutes = require('./speedtest');

const app = express();

app.set('trust proxy', 1);  // <-- taky přidej tady

app.use(cors({
    origin: ['https://tomasekvalla.cz', 'https://www.tomasekvalla.cz', 'https://files.tomasekvalla.cz'],
    credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post('/share-target', (req, res) => res.redirect(303, '/upload.html?share=1'));
app.get('/share-target', (req, res) => res.redirect(302, '/upload.html'));

app.use('/api', uploadRoutes);
app.use('/api/spotify', spotifyRoutes);
app.use('/api', probeRoutes);
app.use('/api', speedtestRoutes);

const PORT = 14150;
app.listen(PORT, '0.0.0.0', () => console.log(`Backend běží na http://0.0.0.0:${PORT}`));