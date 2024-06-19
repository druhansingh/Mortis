const { User } = require("../models/userSchema.js");
const { catchAsyncErrors } = require("./catchAsyncErrors.js");
const ErrorHandler = require("./error.js");
const jwt = require("jsonwebtoken");

// Middleware to authenticate dashboard users
const isAdminAuthenticated = catchAsyncErrors(
  async (req, res, next) => {
    const token = req.cookies.adminToken;
    if (!token) {
      return next(new ErrorHandler("Dashboard User is not authenticated!", 400));
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);
    if (req.user.role !== "Admin") {
      return next(new ErrorHandler(`${req.user.role} not authorized for this resource!`, 403));
    }
    next();
  }
);

// Middleware to authenticate frontend users
const isPatientAuthenticated = catchAsyncErrors(
  async (req, res, next) => {
    const token = req.cookies.patientToken;
    if (!token) {
      return next(new ErrorHandler("User is not authenticated!", 400));
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);
    if (req.user.role !== "Patient") {
      return next(new ErrorHandler(`${req.user.role} not authorized for this resource!`, 403));
    }
    next();
  }
);

const isAuthorized = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new ErrorHandler(`${req.user.role} not allowed to access this resource!`));
    }
    next();
  };
};

module.exports = {
  isAdminAuthenticated,
  isPatientAuthenticated,
  isAuthorized
};
