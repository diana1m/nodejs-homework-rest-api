const gravatar = require('gravatar');
const Jimp = require("jimp");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const fs = require("fs/promises");
const path = require("path");

const { HttpError } = require("../helpers");
const ctrlWrapper = require("../decorators/ctrlWrapper");
const { User }= require("../models/users");

const { SECRET_KEY } = process.env;

const avatarPath = path.resolve("public", "avatars");

const register = ctrlWrapper(async (req, res) => {
    const {email, password} = req.body;
    const user = await User.findOne({email});
    if(user) {
        throw new HttpError(409, "Email already exist");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email);
    const result = await User.create({...req.body, password: hashPassword, avatarURL});

    res.status(201).json({
        user:{
            email: result.email,
            subscription: "starter"
        }
    })
})

const login = ctrlWrapper( async(req, res) => {
    const {email, password} = req.body;

    const user = await User.findOne({email});
    if(!user) {
        throw new  HttpError(401, "Email or password is wrong");
    }

    const isPasswordCompare = await bcrypt.compare(password, user.password);

    if(!isPasswordCompare){
        throw new HttpError(401, "Email or password is wrong");
    }

    const {_id: id} = user;

    const payload = {
        id,
    }

    const token = jwt.sign(payload, SECRET_KEY, {expiresIn: "23h"});
    await User.findByIdAndUpdate(id, {token});

    res.json({
        token,
        user:{
            email: user.email,
            subscription: user.subscription
        }
    })
})

const getCurrent = ctrlWrapper( async(req, res) => {
    const {email, subscription} = req.user;

    res.json({
        email,
        subscription,
    })
})

const logout = ctrlWrapper( async(req, res) => {
    const {_id} = req.user;

    await User.findByIdAndUpdate(_id, {token: null});

    res.status(204).json({
        message: "Logout success"
    })
})

const updateAvatar = ctrlWrapper( async(req, res) => {
    const {_id: id} = req.user;

    const {path: oldPath, originalname} = req.file;
    const filename = `${id}_${originalname}`
    const newPath = path.join(avatarPath, filename);

    const image = await Jimp.read(oldPath);
    image.resize(250, 250);
    await image.writeAsync(oldPath);

    await fs.rename(oldPath, newPath);
    const avatarURL = path.join("avatars", filename);

    await User.findByIdAndUpdate(id, {avatarURL});

    res.json({
        avatarURL,
    })
})

module.exports = {
    register,
    login,
    getCurrent, 
    logout,
    updateAvatar,
}