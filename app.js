require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({msg: "Hello World"})
})

/app.get("/user/:id", checkToken, async(req, res) => {
    const id = req.params.id
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: "Ususario nao encontrado"})
    }
    res.status(200).json({user})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg: "Acesso Negado"})
    }

    try{
        const secret = process.env.secret
        jwt.verify(token, secret)
        next()
    }catch(err){
        res.status(400).json({msg: "Token Invalido"})
    }
}

app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body

    if(!name) {
        return res.status(422).json({msg: 'Error: nome obrigatorio'})
    }

    if(!email) {
        return res.status(422).json({msg: 'Error: email obrigatorio'})
    }

    if(!password) {
        return res.status(422).json({msg: 'Error: senha obrigatorio'})
    }

    if(password !== confirmpassword){
        return res.status(422).json({msg: "Error: senhas nao conferem"})
    }

    const userExist = await User.findOne({email: email})
    if(userExist) {
        return res.status(422).json({msg: "Error: Usuario ja existe"})
    }

    const salt = await bcrypt.genSalt(12)
    const passWordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name, 
        email, 
        password: passWordHash
    })

    try{
        await user.save()
        res.status(201).json({msg: "Usuario criado com sucesso!"})
    } catch(error){
        res.status(500).json({msg: "Aconteceu um error"})
    }
})


app.post('/auth/login', async(req, res) => {
    const {email, password} = req.body

    if(!email) {
        return res.status(422).json({msg: 'Error: nome obrigatorio'})
    }

    if(!password) {
        return res.status(422).json({msg: 'Error: password obrigatorio'})
    }

    const user = await User.findOne({email: email})
    if(!user) {
        return res.status(404).json({msg: "Error: Usuario nao encontrado"})
    }

    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword) {
        return res.status(422).json({msg: "Error: senha invalida"})
    }

    try{
        const secret = process.env.secret
        const token = jwt.sign(
            {
                id: user._id
            },
                secret            
        )

        res.status(200).json({msg: "Autenticação realizada com sucesso", token})
    } catch (err){
        res.status(500).json({msg: "Error: Tente novamente mais tarde"})
    }

})


const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASSWORD

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.0jsohav.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(3000)
    console.log('Conectou ao banco')
}).catch((err) => {
    console.log(err)
})
