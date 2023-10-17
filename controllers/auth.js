const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { BadRequestError, UnauthenticatedError } = require("../errors");
require("dotenv").config();

const register = async (req, res) => {
  const user = await User.create({ ...req.body });
  const token = user.createJWT();
  res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new BadRequestError("Email/Password not provided");
  }
  const user = await User.findOne({ email });
  if (!user) {
    throw new UnauthenticatedError("Invalid Credentials");
  }
  const isPasswordMatch = await user.comparePassword(password);
  if (!isPasswordMatch) {
    throw new UnauthenticatedError("Invalid Credentials");
  }
  const token = user.createJWT();
  res.status(StatusCodes.ACCEPTED).json({ user: { name: user.name }, token });
};

module.exports = {
  register,
  login,
};
