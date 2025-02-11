const express = require('express');
const router = express.Router();

const validateBody = require('../../decorators/validateBody');

const { userValidationSchema, userEmailValidationSchema } = require('../../schemas/userValidationSchema');
const {register, login, getCurrent, logout, verify, resendVerifyEmail} = require("../../controllers/authControllers");

const authenticate = require("../../middlewares/authenticate");
const upload = require("../../middlewares/upload");

router
.route("/register")
.post(validateBody(userValidationSchema), register);

router
.route("/verify/:verificationCode")
.get(verify);

router
.route("/verify")
.post(validateBody(userEmailValidationSchema), resendVerifyEmail);

router
.route("/login")
.post(validateBody(userValidationSchema), login);

router
.route("/current")
.get(authenticate, getCurrent)

router
.route("/logout")
.post(authenticate, logout);

router
.route("/users/avatars")
.patch(authenticate, upload.single("avatar"), updateAvatar);

module.exports = router