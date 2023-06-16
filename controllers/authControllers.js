
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {nanoid} = require("nanoid");

const { HttpError, sendEmail } = require("../helpers");
const ctrlWrapper = require("../decorators/ctrlWrapper");
const { User }= require("../models/users");

const { SECRET_KEY, PROJECT_URL } = process.env;

const register = ctrlWrapper(async (req, res) => {
    const {email, password} = req.body;
    const user = await User.findOne({email});
    if(user) {
        throw new HttpError(409, "Email already exist");
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const verificationCode = nanoid()

    const result = await User.create({...req.body, password: hashPassword, verificationCode});

    const verifyEmail = {
        to: email,
        subject: "Verify email",
        html: `<a target="_blank" href="${PROJECT_URL}/api/auth/verify/${verificationCode}">Click to verify email</a>`
    };

    await sendEmail(verifyEmail);

    res.status(201).json({
        user:{
            email: result.email,
            subscription: "starter"
        }
    })
})


const verify = ctrlWrapper( async(req, res)=> {
    const {verificationCode} = req.params;
    const user = await User.findOne({verificationCode});
    if(!user) {
        throw HttpError(404);
    }
    await User.findByIdAndUpdate(user._id, {verify: true, verificationCode: null});

    res.json({
        message: "Verify success"
    })
})


const resendVerifyEmail = ctrlWrapper(async(req, res) => {
    const {email} = req.body;
    const user = await User.findOne({email});
    if(!user) {
        throw HttpError(404);
    }
    if(user.verify){
        throw HttpError(400, "Verification has already been passed")
    }
    
    const verifyEmail = {
        to: email,
        subject: "Verify email",
        html: `<a target="_blank" href="${PROJECT_URL}/api/auth/verify/${user.verificationCode}">Click to verify email</a>`
    };

    await sendEmail(verifyEmail);

    res.json({
        message: "Verify email send"
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
    
    if(!user.verify) {
        throw new HttpError(401, "User is not verified");
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


const logout = ctrlWrapper( async (req, res) => {
    const {_id} = req.user;

    await User.findByIdAndUpdate(_id, {token: null});

    res.status(204).json({
        message: "Logout success"
    })
})

module.exports = {
    register,
    verify,
    resendVerifyEmail,
    login,
    getCurrent, 
    logout,
}