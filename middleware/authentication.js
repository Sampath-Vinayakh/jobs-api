const jwt = require("jsonwebtoken");
const { CustomAPIError, UnauthenticatedError } = require("../errors");

const authenticationMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("Authentication Invalid");
  }
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const { userId, name } = payload;
    req.user = { userId, name };
    next();
  } catch (err) {
    throw new UnauthenticatedError("Authentication Invalid");
  }
};

module.exports = authenticationMiddleware;
