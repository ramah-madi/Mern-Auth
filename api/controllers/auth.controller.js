import User from "../models/user.model.js";
import bcryptjs from 'bcryptjs';
import { errorHandler } from "../utils/error.js";
import jwt from 'jsonwebtoken';

export const signup = async (req, res, next) => {
    const { username, email, password } = req.body;
    // Use bcryptjs instead of bcrypt becuase bcrypt may cause problems in production.
    const hashedPassword = bcryptjs.hashSync(password, 10);
    const newUser = new User({ username, email, password: hashedPassword});
    try {
        await newUser.save();
        res.status(201).json({message: "User created successfully"});
    } catch (error) {
        next(error);
    };
    
}; 

export const signin = async (req, res, next) => {
    const { email, password } = req.body;
    try {
        // Verify user email
        const validUser = await User.findOne({ email });
        if(!validUser) return next(errorHandler(404, 'User not found'));
        // Verify user password 
        const validPassword = bcryptjs.compareSync(password, validUser.password);
        if (!validPassword) return next(errorHandler(401, 'wrong credentials'));
        // A token that contain encrypted user info that lives in user cookie.
        const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);
        // Seperate the password from the rest of the data.
        const { password: hashedPassword, ...rest } = validUser._doc;
        // Add expiry date
        const expiryDate = new Date(Date.now() + 3600000); // 1 hour
        res.cookie('access_token', token, { httpOnly: true, expires: expiryDate }).status(200).json(rest);
    } catch (error) {
        next(error)
    } 
};