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

userSchema.pre("save", async function(next){ // this will hash password before saving in db
    if(!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password, 10);
});

userSchema.methods.isPasswordCorrect = async function(password){ // this will create custom method and compare password
   return await bcrypt.compare(password, this.password);
};

const User = mongoose.model("User", userSchema);
module.exports = User;