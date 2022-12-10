const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    passwordChangedAt: req.body.passwordChangedAt,
    role: req.body.role
  });

  const token = signToken(newUser._id);
  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser
    }
  });
});

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select('+password');
  // console.log(user);
  // check if email and password exist
  if (!email || !password) {
    return next(new AppError('please provide email or passsword', 400));
  }
  //check if user exist and password is correct
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('incorrect email or passsword', 401));
  }
  // if everything is ok send token to the client
  const token = signToken(user._id);
  res.status(200).json({
    status: 'success',
    token
  });
};

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  // getting token and check if it there
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(new AppError('you are not lol loggedin! please login', 401));
  }
  //verification of token
  const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  //check user still exist
  // const freshUser = await User.findOne({ _id: decode.id });
  const currentUser = await User.findById(decode.id);
  if (!currentUser) {
    return next(
      new AppError('token belonging to this user does not exist', 401)
    );
  }
  //check if the user have changed the password after token is issued
  if (currentUser.changedPasswordAfter(decode.iat)) {
    return next(
      new AppError('user have changed the password! please login again')
    );
  }
  //GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser; //ADD FIELD NAME USER IN REQ
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes.req.user.role) {
      return next(new AppError('you do not have access to this route', 403));
    }
    next();
  };
};

exports.forgetPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError('user with this email does not exist', 404));
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  console.log(resetToken);
  next();
});
