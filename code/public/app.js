const firebaseConfig = {
  apiKey: "AIzaSyAA_Vg-CFhVAcJZ_cGzWVjBSQg6M6y_yP0",
  authDomain: "encryption-32cdc.firebaseapp.com",
  databaseURL: "https://encryption-32cdc-default-rtdb.firebaseio.com",
  projectId: "encryption-32cdc",
  storageBucket: "encryption-32cdc.firebasestorage.app",
  messagingSenderId: "803690663600",
  appId: "1:803690663600:web:9e57087aa36539c1867575",
  measurementId: "G-0NZB2HKPGM"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();
const realtimeDb = firebase.database();

let ec = null;

// Отслеживание попыток входа
const loginAttempts = {};

async function waitForElliptic() {
    return new Promise((resolve, reject) => {
        if (typeof elliptic !== 'undefined') {
            ec = new elliptic.ec('secp256k1');
            console.log('Elliptic загружен');
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/elliptic/6.5.4/elliptic.min.js';
        script.onload = () => {
            ec = new elliptic.ec('secp256k1');
            console.log('Elliptic загружен с CDN');
            resolve();
        };
        script.onerror = () => reject(new Error('Не удалось загрузить библиотеку elliptic'));
        document.head.appendChild(script);
    });
}

class Rabin {
    constructor() {
        this.p = this.generatePrime(64);
        this.q = this.generatePrime(64);
        while (this.p === this.q) this.q = this.generatePrime(64);
        this.n = this.p * this.q;
    }
    
    generatePrime(bits) {
        const max = 2 ** Math.min(bits, 20);
        let num = BigInt(Math.floor(Math.random() * max) | 1);
        if (num < 3n) num = 3n;
        if (num % 2n === 0n) num += 1n;
        
        let attempts = 0;
        while (!this.isPrime(num) && attempts < 1000) {
            num += 2n;
            attempts++;
        }
        
        if (attempts >= 1000) {
            console.warn('Не удалось найти простое число, используем предустановленное');
            return 61n;
        }
        
        return num;
    }
    
    isPrime(num) {
        if (num < 2n) return false;
        if (num === 2n || num === 3n) return true;
        if (num % 2n === 0n) return false;
        
        const limit = BigInt(Math.floor(Math.sqrt(Number(num))));
        for (let i = 3n; i <= limit; i += 2n) {
            if (num % i === 0n) return false;
        }
        return true;
    }
    
    encrypt(m) {
        const msg = BigInt(m.charCodeAt(0));
        return (msg * msg) % this.n;
    }
    
    decrypt(c) {
        const mp = this.modSqrt(c, this.p);
        return mp;
    }
    
    modSqrt(a, p) {
        return a ** ((p + 1n) / 4n) % p;
    }
}

let currentChatId = null;
let currentMethod = null;
let recipientPublic = null;
let activeEncryptionMethod = null;
let recipientUsername = null;
let usersCache = {};

const routes = {
    '/': renderHome,
    '/register': renderRegister,
    '/login': renderLogin,
    '/pricing': renderPricing,
    '/chat': renderChat,
    '/admin': renderAdmin,
    '/security': renderSecurity
};

function navigate(path) {
    history.pushState({}, '', path);
    renderPage(path);
}

async function renderPage(path) {
    const content = document.getElementById('content');
    if (!content) return;
    content.innerHTML = '';
    content.className = 'content';

    const user = auth.currentUser;
    const logoutBtn = document.getElementById('logout');
    if (logoutBtn) logoutBtn.style.display = user ? 'block' : 'none';
    
    const adminLink = document.querySelector('.admin-link');
    const securityLink = document.querySelector('.security-link');
    if (adminLink) adminLink.style.display = 'none';
    if (securityLink) securityLink.style.display = 'none';

    if (user) {
        try {
            const doc = await db.collection('users').doc(user.uid).get();
            if (doc.exists) {
                const role = doc.data().role;
                if (role === 'admin' && adminLink) adminLink.style.display = 'block';
                if (role === 'engineer' && securityLink) securityLink.style.display = 'block';
            }
        } catch (e) { console.error(e); }
    }

    const func = routes[path] || (() => content.innerHTML = '<h1>404 Not Found</h1>');
    if (['/pricing', '/chat', '/admin', '/security'].includes(path) && !user) {
        navigate('/login');
        return;
    }
    
    // Проверка доступа к админ/инженер панелям
    if (path === '/admin' || path === '/security') {
        const userDocCheck = await db.collection('users').doc(user.uid).get();
        if (userDocCheck.exists) {
            const userRole = userDocCheck.data().role;
            if (path === '/admin' && userRole !== 'admin') {
                navigate('/chat');
                return;
            }
            if (path === '/security' && userRole !== 'engineer') {
                navigate('/chat');
                return;
            }
        }
    }
    
    func(content);
}

function renderHome(content) {
    content.classList.add('gradient-bg');
    content.innerHTML = `
        <h1>Добро пожаловать на платформу для защиты данных!</h1>
        <p>Наш сайт посвящен использованию криптографических методов (ECC и Rabin) для безопасного обмена данными.</p>
        <button class="btn gradient-btn" onclick="navigate('/register')">Регистрация</button>
        <button class="btn gradient-btn" onclick="navigate('/login')">Войти</button>
    `;
}

function renderRegister(content) {
    if (auth.currentUser) return navigate('/pricing');
    content.classList.add('gradient-bg');
    content.innerHTML = `
        <h2>Регистрация</h2>
        <div class="form">
            <input class="input" type="email" id="regEmail" placeholder="Email" required>
            <input class="input" type="password" id="regPass" placeholder="Пароль" required>
            <button class="btn gradient-btn" id="regBtn">Зарегистрироваться</button>
        </div>
    `;
    document.getElementById('regBtn').onclick = async () => {
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPass').value;
        try {
            const cred = await auth.createUserWithEmailAndPassword(email, password);
            await cred.user.sendEmailVerification();
            const username = email.split('@')[0] + Math.floor(Math.random() * 10000);
            await db.collection('users').doc(cred.user.uid).set({
                email, username, role: 'user',
                blocked: false,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
            });
            alert(`Успех! Логин: ${username}`);
            navigate('/pricing');
        } catch (err) {
            alert('Ошибка: ' + err.message);
        }
    };
}

function renderLogin(content) {
    if (auth.currentUser) return navigate('/pricing');
    content.classList.add('gradient-bg');
    content.innerHTML = `
        <h2>Вход</h2>
        <div class="form">
            <input class="input" type="email" id="loginEmail" placeholder="Email" required>
            <input class="input" type="password" id="loginPass" placeholder="Пароль" required>
            <button class="btn gradient-btn" id="loginBtn">Войти</button>
        </div>
    `;
    document.getElementById('loginBtn').onclick = async () => {
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPass').value;
        
        // Отслеживание попыток входа
        if (!loginAttempts[email]) {
            loginAttempts[email] = { count: 0, lastAttempt: Date.now() };
        }
        
        try {
            await auth.signInWithEmailAndPassword(email, password);
            
            // Проверка блокировки
            const userDoc = await db.collection('users').doc(auth.currentUser.uid).get();
            if (userDoc.exists && userDoc.data().blocked) {
                await auth.signOut();
                alert('Ваш аккаунт заблокирован');
                return;
            }
            
            // Проверяем роль и перенаправляем соответственно
            const userRole = userDoc.data().role;
            if (userRole === 'admin') {
                navigate('/admin');
            } else if (userRole === 'engineer') {
                navigate('/security');
            } else {
                navigate('/pricing');
            }
            
            // Сброс попыток при успешном входе
            loginAttempts[email] = { count: 0, lastAttempt: Date.now() };
        } catch (err) {
            // Увеличиваем счетчик попыток
            loginAttempts[email].count++;
            loginAttempts[email].lastAttempt = Date.now();
            
            console.log('Попытка входа №', loginAttempts[email].count, 'для', email);
            
            // Если 5 или больше попыток
            if (loginAttempts[email].count >= 5) {
                try {
                    // Создаем отчет для инженера безопасности
                    await db.collection('security_reports').add({
                        email: email,
                        attempts: loginAttempts[email].count,
                        timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                        type: 'multiple_failed_logins',
                        status: 'pending'
                    });
                    console.log('Отчет создан для', email);
                    alert('Обнаружено много неудачных попыток входа. Отчет отправлен службе безопасности.');
                } catch (reportErr) {
                    console.error('Ошибка создания отчета:', reportErr);
                }
            } else {
                // Показываем обычную ошибку входа
                alert('Ошибка входа: ' + err.message);
            }
        }
    };
}

async function createSecurityReport(email, attempts) {
    const oneHourAgo = firebase.firestore.Timestamp.fromDate(new Date(Date.now() - 3600000));
    const recent = await db.collection('security_reports')
        .where('email', '==', email)
        .where('type', '==', 'multiple_failed_logins')
        .where('status', '==', 'pending')
        .where('timestamp', '>', oneHourAgo)
        .limit(1)
        .get();
    
    if (recent.empty) {
        await db.collection('security_reports').add({
            email: email,
            attempts: attempts,
            timestamp: firebase.firestore.FieldValue.serverTimestamp(),
            type: 'multiple_failed_logins',
            status: 'pending'
        });
        return true;
    }
    return false;
}

async function renderPricing(content) {
    const user = auth.currentUser;
    if (!user) return navigate('/login');
    
    const doc = await db.collection('users').doc(user.uid).get();
    
    // Проверяем роль - если админ или инженер, они могут пропустить тариф
    if (doc.exists) {
        const userRole = doc.data().role;
        if (userRole === 'admin') {
            navigate('/admin');
            return;
        }
        if (userRole === 'engineer') {
            navigate('/security');
            return;
        }
        // Если уже есть тариф, идем в чат
        if (doc.data().tariff) {
            navigate('/chat');
            return;
        }
    }

    content.innerHTML = `
        <h2>Выберите тариф</h2>
        <div class="card-container">
            <div class="card">
                <h3>Базовый</h3>
                <p>$5/месяц</p>
                <select id="methodBasic">
                    <option value="ECC">ECC</option>
                    <option value="Rabin">Rabin</option>
                </select>
                <button class="btn gradient-btn" onclick="subscribe('basic', document.getElementById('methodBasic').value)">Подключить</button>
            </div>
            <div class="card">
                <h3>Премиум</h3>
                <p>$15/месяц</p>
                <p>Оба метода</p>
                <button class="btn gradient-btn" onclick="subscribe('premium', 'both')">Подключить</button>
            </div>
        </div>
    `;
}

async function subscribe(tariff, method) {
    try {
        const uid = auth.currentUser.uid;
        if (!uid) {
            alert('Ошибка авторизации');
            return;
        }

        if ((method === 'ECC' || method === 'both') && !ec) {
            alert('Загружаем библиотеку шифрования ECC...');
            try {
                await waitForElliptic();
            } catch (e) {
                alert('Ошибка загрузки библиотеки ECC: ' + e.message);
                return;
            }
        }

        alert('Оплата симулирована. Активируем тариф...');

        const userRef = db.collection('users').doc(uid);
        const doc = await userRef.get();
        if (!doc.exists) {
            await userRef.set({
                email: auth.currentUser.email || 'unknown',
                username: auth.currentUser.email?.split('@')[0] || 'user',
                role: 'user',
                blocked: false,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
            });
        }

        await userRef.update({
            tariff: tariff,
            encryptionMethod: method,
            subscriptionStart: firebase.firestore.FieldValue.serverTimestamp()
        });

        if (method === 'ECC' || method === 'both') {
            const keyPair = ec.genKeyPair();
            const privateKey = keyPair.getPrivate('hex');
            const publicKey = keyPair.getPublic('hex');
            
            localStorage.setItem('privateKey', privateKey);
            await userRef.update({ publicKey: publicKey });
        }

        if (method === 'Rabin' || method === 'both') {
            const rabin = new Rabin();
            
            localStorage.setItem('rabinP', rabin.p.toString());
            localStorage.setItem('rabinQ', rabin.q.toString());
            await userRef.update({ rabinN: rabin.n.toString() });
        }

        alert('Тариф успешно подключён!');
        navigate('/chat');

    } catch (error) {
        console.error('Ошибка в subscribe:', error);
        alert('Ошибка: ' + error.message);
    }
}

async function renderChat(content) {
    const user = auth.currentUser;
    if (!user) return navigate('/login');
    const userDoc = await db.collection('users').doc(user.uid).get();
    if (!userDoc.exists || !userDoc.data().tariff) return navigate('/pricing');

    const myMethod = userDoc.data().encryptionMethod;

    content.innerHTML = `
        <div class="chat-container">
            <div class="chat-header">
                <button class="btn" id="backBtn" style="float:left;padding:0.5rem 1rem;background:rgba(255,255,255,0.2);display:none;">← Назад</button>
                <span id="chatTitle">Выберите собеседника</span>
            </div>
            <ul class="list" id="usersList"></ul>
            <div id="chatArea" style="display:none;">
                <div class="chat-messages" id="messages"></div>
                <div class="chat-input">
                    <input class="input" id="messageInput" placeholder="Введите сообщение...">
                    <button class="btn gradient-btn" onclick="sendMessage()">Отправить</button>
                </div>
            </div>
        </div>
    `;

    document.getElementById('backBtn').onclick = () => {
        if (window.chatListener) {
            window.chatListener();
            window.chatListener = null;
        }
        document.getElementById('usersList').style.display = 'block';
        document.getElementById('chatArea').style.display = 'none';
        document.getElementById('backBtn').style.display = 'none';
        document.getElementById('chatTitle').textContent = 'Выберите собеседника';
    };

    const snapshot = await db.collection('users').get();
    const list = document.getElementById('usersList');
    list.innerHTML = '';
    
    usersCache = {};
    
    snapshot.forEach(doc => {
        const userData = doc.data();
        usersCache[doc.id] = userData.username || userData.email || 'Пользователь';
        
        if (doc.id !== user.uid) {
            const theirMethod = userData.encryptionMethod;
            let compatible = false;
            if (myMethod === 'both' || theirMethod === 'both') {
                compatible = true;
            } else if (myMethod === theirMethod) {
                compatible = true;
            }

            const li = document.createElement('li');
            li.textContent = usersCache[doc.id] + 
                             (compatible ? '' : ' (несовместимый метод)');
            li.style.cursor = compatible ? 'pointer' : 'not-allowed';
            li.style.opacity = compatible ? '1' : '0.5';
            li.style.padding = '12px';
            li.style.background = '#f8f8f8';
            li.style.margin = '8px 0';
            li.style.borderRadius = '12px';

            if (compatible) {
                li.onclick = () => startChat(doc.id, usersCache[doc.id], myMethod, userData);
            }
            list.appendChild(li);
        }
    });
}

async function startChat(recipientId, username, myMethod, recipientData) {
    currentChatId = [auth.currentUser.uid, recipientId].sort().join('_');
    currentMethod = myMethod;
    recipientUsername = username;
    
    const theirMethod = recipientData.encryptionMethod;
    
    if (myMethod === 'both' && theirMethod === 'both') {
        activeEncryptionMethod = 'ECC';
        recipientPublic = recipientData.publicKey;
    } else if (myMethod === 'both') {
        activeEncryptionMethod = theirMethod;
        recipientPublic = theirMethod === 'ECC' ? recipientData.publicKey : recipientData.rabinN;
    } else if (theirMethod === 'both') {
        activeEncryptionMethod = myMethod;
        recipientPublic = myMethod === 'ECC' ? recipientData.publicKey : recipientData.rabinN;
    } else {
        activeEncryptionMethod = myMethod;
        recipientPublic = myMethod === 'ECC' ? recipientData.publicKey : recipientData.rabinN;
    }

    if (!recipientPublic) {
        alert('Собеседник не имеет нужного публичного ключа.');
        return;
    }

    document.getElementById('chatTitle').textContent = `Чат с ${username} (${activeEncryptionMethod})`;
    document.getElementById('backBtn').style.display = 'block';
    document.getElementById('usersList').style.display = 'none';
    document.getElementById('chatArea').style.display = 'block';
    document.getElementById('messages').innerHTML = '<p style="text-align:center;color:#999;">Загрузка сообщений...</p>';

    if (window.chatListener) {
        window.chatListener();
        window.chatListener = null;
    }

    const ref = realtimeDb.ref(`chats/${currentChatId}`);
    
    try {
        const snapshot = await ref.once('value');
        const messagesDiv = document.getElementById('messages');
        messagesDiv.innerHTML = '';
        
        if (!snapshot.exists()) {
            messagesDiv.innerHTML = '<p style="text-align:center;color:#999;">Начните общение! Напишите первое сообщение.</p>';
        } else {
            let messageCount = 0;
            snapshot.forEach(childSnap => {
                const msg = childSnap.val();
                if (msg && msg.encrypted && msg.method) {
                    displayMessage(msg);
                    messageCount++;
                }
            });
            
            if (messageCount === 0) {
                messagesDiv.innerHTML = '<p style="text-align:center;color:#999;">Нет сообщений. Напишите первое!</p>';
            }
        }
    } catch (e) {
        console.error('Ошибка загрузки истории:', e);
        document.getElementById('messages').innerHTML = '<p style="text-align:center;color:#f00;">Ошибка загрузки истории</p>';
    }
    
    const listener = ref.limitToLast(1).on('child_added', snap => {
        const msg = snap.val();
        if (!msg || !msg.encrypted || !msg.method) return;
        
        const timestamp = msg.timestamp;
        const now = Date.now();
        
        if (timestamp && (now - timestamp > 2000)) {
            return;
        }
        
        displayMessage(msg);
    });
    
    window.chatListener = () => ref.off('child_added', listener);
}

function displayMessage(msg) {
    let decrypted = '[Не удалось расшифровать]';
    try {
        decrypted = decryptMessage(msg.encrypted, msg.method);
    } catch (e) {
        console.error('Ошибка расшифровки:', e);
        decrypted = '[Ошибка: ' + e.message + ']';
    }

    const messagesDiv = document.getElementById('messages');
    
    const placeholder = messagesDiv.querySelector('p[style*="text-align:center"]');
    if (placeholder) {
        placeholder.remove();
    }

    const isMyMessage = msg.sender === auth.currentUser.uid;
    
    const container = document.createElement('div');
    container.style.display = 'flex';
    container.style.flexDirection = 'column';
    container.style.alignItems = isMyMessage ? 'flex-end' : 'flex-start';
    container.style.marginBottom = '1rem';
    
    const senderName = document.createElement('div');
    senderName.style.fontSize = '0.75em';
    senderName.style.color = '#666';
    senderName.style.marginBottom = '4px';
    senderName.style.marginLeft = isMyMessage ? '0' : '12px';
    senderName.style.marginRight = isMyMessage ? '12px' : '0';
    senderName.style.fontWeight = '600';
    
    if (isMyMessage) {
        senderName.textContent = 'Вы';
    } else {
        senderName.textContent = recipientUsername || usersCache[msg.sender] || 'Собеседник';
    }
    
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', isMyMessage ? 'sent' : 'received');
    messageDiv.style.maxWidth = '70%';
    messageDiv.style.wordWrap = 'break-word';
    messageDiv.textContent = decrypted;
    
    const timeDiv = document.createElement('div');
    timeDiv.style.fontSize = '0.65em';
    timeDiv.style.color = isMyMessage ? 'rgba(255,255,255,0.8)' : 'rgba(255,255,255,0.8)';
    timeDiv.style.marginTop = '4px';
    timeDiv.style.textAlign = 'right';
    
    if (msg.timestamp) {
        const date = new Date(msg.timestamp);
        const time = date.toLocaleTimeString('ru-RU', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
        const dateStr = date.toLocaleDateString('ru-RU', {
            day: '2-digit',
            month: '2-digit'
        });
        
        const today = new Date();
        const isToday = date.toDateString() === today.toDateString();
        
        timeDiv.textContent = isToday ? time : `${dateStr} ${time}`;
    } else {
        timeDiv.textContent = 'Отправка...';
    }
    
    messageDiv.appendChild(timeDiv);
    container.appendChild(senderName);
    container.appendChild(messageDiv);
    
    messagesDiv.appendChild(container);
    container.scrollIntoView({ behavior: 'smooth', block: 'end' });
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const msg = input.value.trim();
    if (!msg) return;

    try {
        const encrypted = encryptMessage(msg, activeEncryptionMethod);
        realtimeDb.ref(`chats/${currentChatId}`).push({
            encrypted: encrypted,
            method: activeEncryptionMethod,
            sender: auth.currentUser.uid,
            timestamp: firebase.database.ServerValue.TIMESTAMP
        });
        input.value = '';
    } catch (e) {
        alert('Ошибка шифрования: ' + e.message);
        console.error(e);
    }
}

document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const input = document.getElementById('messageInput');
        if (input && document.activeElement === input) {
            sendMessage();
        }
    }
});

function encryptMessage(msg, method) {
    if (method === 'ECC') {
        if (!ec) throw new Error("Библиотека ECC не загружена");
        if (!recipientPublic) throw new Error("Нет публичного ключа ECC у собеседника");
        
        const pub = ec.keyFromPublic(recipientPublic, 'hex');
        const ephemeral = ec.genKeyPair();
        const shared = ephemeral.derive(pub.getPublic()).toString(16);
        
        let encrypted = '';
        for (let i = 0; i < msg.length; i++) {
            const charCode = msg.charCodeAt(i);
            const keyChar = parseInt(shared.substr((i * 2) % shared.length, 2), 16);
            encrypted += String.fromCharCode(charCode ^ keyChar);
        }
        
        return ephemeral.getPublic('hex') + ':' + btoa(encrypted);
    }

    if (method === 'Rabin') {
        if (!recipientPublic) throw new Error("Нет публичного ключа Rabin у собеседника");
        
        const n = BigInt(recipientPublic);
        let encryptedParts = [];
        for (let char of msg) {
            const m = BigInt(char.charCodeAt(0));
            const c = (m * m) % n;
            encryptedParts.push(c.toString());
        }
        return encryptedParts.join(',');
    }

    throw new Error("Неизвестный метод шифрования: " + method);
}

function decryptMessage(encrypted, method) {
    if (method === 'ECC') {
        const priv = localStorage.getItem('privateKey');
        if (!priv) return "[Нет ключа ECC]";
        
        try {
            const [ephemeralPub, encryptedData] = encrypted.split(':');
            const keyPair = ec.keyFromPrivate(priv, 'hex');
            const ephemeral = ec.keyFromPublic(ephemeralPub, 'hex');
            const shared = keyPair.derive(ephemeral.getPublic()).toString(16);
            
            const encryptedMsg = atob(encryptedData);
            let decrypted = '';
            for (let i = 0; i < encryptedMsg.length; i++) {
                const charCode = encryptedMsg.charCodeAt(i);
                const keyChar = parseInt(shared.substr((i * 2) % shared.length, 2), 16);
                decrypted += String.fromCharCode(charCode ^ keyChar);
            }
            return decrypted;
        } catch (e) {
            return "[Ошибка ECC: " + e.message + "]";
        }
    }

    if (method === 'Rabin') {
        const p = BigInt(localStorage.getItem('rabinP') || '0');
        const q = BigInt(localStorage.getItem('rabinQ') || '0');
        
        if (p === 0n || q === 0n) return "[Нет ключей Rabin в localStorage]";

        const n = p * q;
        let decrypted = '';
        const parts = encrypted.split(',');
        
        for (let cStr of parts) {
            const c = BigInt(cStr);
            let m = (c ** ((p + 1n) / 4n)) % p;
            
            if ((m * m) % n !== c % n) {
                m = (c ** ((q + 1n) / 4n)) % q;
            }
            
            decrypted += String.fromCharCode(Number(m % 256n));
        }
        
        return decrypted;
    }

    return "[Неизвестный метод: " + method + "]";
}

// ПАНЕЛЬ БЕЗОПАСНОСТИ (инженер)
async function renderSecurity(content) {
    const user = auth.currentUser;
    if (!user) return navigate('/login');
    
    const userDoc = await db.collection('users').doc(user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== 'engineer') {
        content.innerHTML = '<h2>Доступ запрещен</h2>';
        return;
    }
    
    content.innerHTML = `
        <div class="admin-panel">
            <h2>Панель безопасности</h2>
            <p>Отчеты о подозрительной активности</p>
            <div id="reportsList"></div>
        </div>
    `;
    
    const reportsList = document.getElementById('reportsList');
    
    try {
        const snapshot = await db.collection('security_reports')
            .where('status', '==', 'pending')
            .limit(50)
            .get();
        
        if (snapshot.empty) {
            reportsList.innerHTML = '<p style="text-align:center;color:#999;">Нет активных отчетов</p>';
            return;
        }
        
        // Сортируем на клиенте
        const reports = [];
        snapshot.forEach(doc => {
            reports.push({ id: doc.id, data: doc.data() });
        });
        
        reports.sort((a, b) => {
            const timeA = a.data.timestamp ? a.data.timestamp.toMillis() : 0;
            const timeB = b.data.timestamp ? b.data.timestamp.toMillis() : 0;
            return timeB - timeA;
        });
        
        reports.forEach(item => {
            const report = item.data;
            const div = document.createElement('div');
            div.className = 'report-item';
            div.innerHTML = `
                <div style="background:#fff;padding:1rem;margin:0.5rem 0;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                    <strong>Email:</strong> ${report.email}<br>
                    <strong>Попыток входа:</strong> ${report.attempts}<br>
                    <strong>Тип:</strong> ${report.type}<br>
                    <strong>Время:</strong> ${report.timestamp ? new Date(report.timestamp.toDate()).toLocaleString('ru-RU') : 'Неизвестно'}<br>
                    <button class="btn" style="margin-top:0.5rem;background:#48bb78;color:#fff;margin-right:0.5rem;" onclick="reportToAdmin('${report.email}', '${item.id}')">Репортнуть</button>
                    <button class="btn" style="margin-top:0.5rem;background:#f56565;color:#fff;" onclick="dismissReport('${item.id}')">Отклонить</button>
                </div>
            `;
            reportsList.appendChild(div);
        });
    } catch (e) {
        console.error('Ошибка загрузки отчетов:', e);
        reportsList.innerHTML = `<p style="color:#f00;">Ошибка загрузки отчетов: ${e.message}</p>`;
    }
}

async function dismissReport(reportId) {
    try {
        await db.collection('security_reports').doc(reportId).update({
            status: 'dismissed'
        });
        alert('Отчет отклонен');
        renderPage('/security');
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

async function reportToAdmin(email, reportId) {
    try {
        // Находим пользователя по email
        const usersSnapshot = await db.collection('users').where('email', '==', email).get();
        
        if (!usersSnapshot.empty) {
            const userId = usersSnapshot.docs[0].id;
            
            // Создаем запрос на блокировку для админа
            await db.collection('admin_requests').add({
                userId: userId,
                email: email,
                reason: 'Подозрительная активность - множественные попытки входа',
                reportId: reportId,
                status: 'pending',
                timestamp: firebase.firestore.FieldValue.serverTimestamp()
            });
            
            // Помечаем отчет как отправленный админу
            await db.collection('security_reports').doc(reportId).update({
                status: 'reported'
            });
            
            alert('Отчет отправлен администратору');
            renderPage('/security');
        } else {
            alert('Пользователь не найден');
        }
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

// АДМИН-ПАНЕЛЬ
async function renderAdmin(content) {
    const user = auth.currentUser;
    if (!user) return navigate('/login');
    
    const userDoc = await db.collection('users').doc(user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== 'admin') {
        content.innerHTML = '<h2>Доступ запрещен</h2>';
        return;
    }
    
    content.innerHTML = `
        <div class="admin-panel">
            <h2>Админ-панель</h2>
            <p>Управление пользователями</p>
            
            <div id="adminRequests" style="margin-bottom:2rem;"></div>
            
            <h3 style="margin-top:2rem;">Все пользователи</h3>
            <div id="usersList"></div>
        </div>
    `;
    
    // Загружаем запросы от инженеров
    const requestsDiv = document.getElementById('adminRequests');
    try {
        const requestsSnapshot = await db.collection('admin_requests')
            .where('status', '==', 'pending')
            .limit(20)
            .get();
        
        if (!requestsSnapshot.empty) {
            requestsDiv.innerHTML = '<h3>Запросы от инженеров безопасности</h3>';
            requestsSnapshot.forEach(doc => {
                const req = doc.data();
                const div = document.createElement('div');
                div.innerHTML = `
                    <div style="background:#fff3cd;padding:1rem;margin:0.5rem 0;border-radius:12px;border:2px solid #ffc107;">
                        <strong>Email:</strong> ${req.email}<br>
                        <strong>Причина:</strong> ${req.reason}<br>
                        <strong>Время:</strong> ${req.timestamp ? new Date(req.timestamp.toDate()).toLocaleString('ru-RU') : 'Неизвестно'}<br>
                        <button class="btn" style="margin-top:0.5rem;background:#f56565;color:#fff;margin-right:0.5rem;" onclick="approveBlock('${req.userId}', '${doc.id}')">Заблокировать</button>
                        <button class="btn" style="margin-top:0.5rem;background:#6c757d;color:#fff;" onclick="denyRequest('${doc.id}')">Отклонить</button>
                    </div>
                `;
                requestsDiv.appendChild(div);
            });
        }
    } catch (e) {
        console.error('Ошибка загрузки запросов:', e);
    }
    
    const usersList = document.getElementById('usersList');
    
    try {
        const snapshot = await db.collection('users').get();
        
        snapshot.forEach(doc => {
            const userData = doc.data();
            const div = document.createElement('div');
            div.className = 'user-item';
            div.innerHTML = `
                <div style="background:#fff;padding:1rem;margin:0.5rem 0;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                    <strong>${userData.username || userData.email}</strong><br>
                    <span style="color:#666;">Email: ${userData.email}</span><br>
                    <span style="color:#666;">Роль: ${userData.role || 'user'}</span><br>
                    <span style="color:${userData.blocked ? '#f56565' : '#48bb78'};">
                        Статус: ${userData.blocked ? 'Заблокирован' : 'Активен'}
                    </span><br>
                    ${userData.blocked ? 
                        `<button class="btn" style="margin-top:0.5rem;background:#48bb78;color:#fff;" onclick="unblockUser('${doc.id}')">Разблокировать</button>` :
                        `<button class="btn" style="margin-top:0.5rem;background:#f56565;color:#fff;" onclick="blockUser('${doc.id}')">Заблокировать</button>`
                    }
                </div>
            `;
            usersList.appendChild(div);
        });
    } catch (e) {
        console.error('Ошибка загрузки пользователей:', e);
        usersList.innerHTML = '<p style="color:#f00;">Ошибка загрузки пользователей</p>';
    }
}

async function blockUser(userId) {
    try {
        await db.collection('users').doc(userId).update({
            blocked: true
        });
        alert('Пользователь заблокирован');
        renderPage('/admin');
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

async function unblockUser(userId) {
    try {
        await db.collection('users').doc(userId).update({
            blocked: false
        });
        alert('Пользователь разблокирован');
        renderPage('/admin');
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

async function approveBlock(userId, requestId) {
    try {
        await db.collection('users').doc(userId).update({
            blocked: true
        });
        await db.collection('admin_requests').doc(requestId).update({
            status: 'approved'
        });
        alert('Пользователь заблокирован');
        renderPage('/admin');
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

async function denyRequest(requestId) {
    try {
        await db.collection('admin_requests').doc(requestId).update({
            status: 'denied'
        });
        alert('Запрос отклонен');
        renderPage('/admin');
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

const logoutBtn = document.getElementById('logout');
if (logoutBtn) {
    logoutBtn.onclick = () => auth.signOut().then(() => navigate('/'));
}

if (typeof elliptic !== 'undefined') {
    ec = new elliptic.ec('secp256k1');
    console.log('Elliptic инициализирован при загрузке');
}

auth.onAuthStateChanged(() => renderPage(location.pathname));
renderPage(location.pathname);

window.navigate = navigate;
window.subscribe = subscribe;
window.sendMessage = sendMessage;
window.dismissReport = dismissReport;
window.reportToAdmin = reportToAdmin;
window.blockUser = blockUser;
window.unblockUser = unblockUser;
window.approveBlock = approveBlock;
window.denyRequest = denyRequest;