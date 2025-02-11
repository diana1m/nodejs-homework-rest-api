const Joi = require("joi");

const userValidationSchema = Joi.object({
    email: Joi.string().email().required("field email is required"),
    password: Joi.string().required("field password is required")
  });

const userEmailValidationSchema = Joi.object({
  email: Joi.string().email().required("field email is required")
});

  module.exports = {userValidationSchema, userEmailValidationSchema}