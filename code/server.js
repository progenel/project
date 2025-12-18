const express = require('express');
const path = require('path');
const app = express();

// Отдаём статические файлы из папки public
app.use(express.static(path.join(__dirname, 'public')));

// Для всех маршрутов — возвращаем index.html (важно для SPA роутинга)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});