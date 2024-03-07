const mongoose = require('mongoose');
const bcrypt = required('bcrypt');
const jwt = required('jsonwebtoken');

const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true,
        index: true
    },

    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },

    fullname: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
    },

    avatar: {
        type: String,
        required: true,
    },

    coverImage: {
        type: String,
        required: true,
    },

    watchHistory: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Video" // It will refer to Video Schema
        }
    ],

    password: {
        type: String,
        required: [true, "Password is required"]

    },

    refreshToken: {
        type: String
    },
}, { timestamps: true });

userSchema.pre("save", async function (next) { // this will hash password before saving in db
    if (!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password, 10);
});

userSchema.methods.isPasswordCorrect = async function (password) { // this will create custom method and compare password and it will inject methods in schema
    return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
    return jwt.sign({
        _id: this._id,
        username: this.username,
        fullName: this.fullName,
        email: this.email
    }, process.env.ACCESS_TOKEN_SECRET, {
        expiredIn: ACCESS_TOKEN_EXPIRY
    });
}

userSchema.methods.generateRefreshToken = function () {
    return jwt.sign({
        _id: this._id,
    }, process.env.REFRESH_TOKEN_SECRET, {
        expiredIn: REFRESH_TOKEN_EXPIRY
    });
}

const User = mongoose.model("User", userSchema);
module.exports = User;