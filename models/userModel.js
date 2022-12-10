const mongoose = require('mongoose');
const validator = require('validator');
const bcryptjs = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: {
      values: true,
      message: 'please provide your name'
    }
  },
  email: {
    type: String,
    required: [true, 'please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'please provide a valid email']
  },
  photo: String,
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'please enter a secure password'],
    minlength: 8,
    select: false
  },
  confirmPassword: {
    type: String,
    required: [true, 'please confirm your password'],
    validate: {
      //this work only in save and create
      validator: function(el) {
        return el === this.password;
      },
      message: 'password is not same'
    }
  },
  passwordChangedAt: {
    type: Date
  },
  passwordResetToken: String,
  passwordResetExpiresIn: Date
});

userSchema.pre('save', async function(next) {
  //run this when paaword is modified
  if (!this.isModified('password')) return next;
  //hash password with cost of 12
  this.password = await bcryptjs.hash(this.password, 12);
  //delete confirm password
  this.confirmPassword = undefined;
  next();
});

userSchema.methods.correctPassword = async function(
  candidatePassword,
  userPasssword
) {
  return await bcryptjs.compare(candidatePassword, userPasssword);
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpiresIn = Date.now() + 10 * 60 * 1000;
  return resetToken;
};
const User = mongoose.model('User', userSchema);

module.exports = User;
