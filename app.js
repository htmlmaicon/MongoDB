require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());

const User = require('./User');

// Rota pública
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem-vindo à nossa API!" });
});

// Middleware para verificar token
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' });
    }

    try {
        const secret = process.env.JWT_SECRET;
        jwt.verify(token, secret);
        next();
    } catch (error) {
        res.status(400).json({ msg: "Token inválido!" });
    }
}

// Rota privada
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    // Checando se usuário existe
    const user = await User.findById(id, '-password');
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' });
    }

    res.status(200).json({ user });
});

// Registrar usuário
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    // Verificação de campos obrigatórios
    if (!name) {
        return res.status(422).json({ msg: "O nome é obrigatório!" });
    }
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }
    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas não conferem!" });
    }

    // Verificação de usuário já existente
    const userExist = await User.findOne({ email: email });
    if (userExist) {
        return res.status(422).json({ msg: "Por favor, utilize outro email." });
    }

    // Criação do hash da senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Criação do novo usuário
    const newUser = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await newUser.save();
        res.status(201).json({ msg: 'Usuário criado com sucesso!' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Erro no servidor.' });
    }
});

// Login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // Verificação de campos obrigatórios
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }
    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }

    try {
        // Verificação de usuário existente
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ msg: "Usuário não encontrado!" });
        }

        // Verificação da senha
        const checkPassword = await bcrypt.compare(password, user.password);
        if (!checkPassword) {
            return res.status(422).json({ msg: "Senha inválida!" });
        }

        // Criação do token
        const secret = process.env.JWT_SECRET;
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
            { expiresIn: '1h' } // Define o tempo de expiração do token
        );

        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: "Erro no servidor." });
    }
});

// Conexão com o MongoDB
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.gj5m4.mongodb.net/seu_nome_do_banco_de_dados?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        console.log('Conexão com o MongoDB bem-sucedida!');
        app.listen(8080, () => console.log('Servidor rodando na porta 8080'));
    })
    .catch((err) => console.log(err));
