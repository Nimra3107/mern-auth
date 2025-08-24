import bcrypt from 'bcryptjs';
import Jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTempltes.js';

//------------register----------------------
export const register = async (req,res) => {
    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message: 'Misiing Details'})
    }
    try {
        const existingUser = await userModel.findOne({email}) //if user already exit

        if(existingUser){
            return res.json({success: false, message: "User already exists"})
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const user = new userModel({name, email, password: hashedPassword}); //if email not exist
        await user.save();

        const token = Jwt.sign({id: user._id},process.env.JWT_SECRET, {expiresIn: '7d'}); //mongodb store id

        res.cookie('token', token, {
            httpOnly: true,   // on live server
            secure: process.env.NODE_ENV === 'production',  //if run on local environment
            sameSite: process.env.NODE_ENV === 'production' ? 'none': 'strict',  //for deployment client and server on differnt domin
            maxAge: 7 * 24 * 60 * 60 * 1000  //cookie expire time in milisecond
        });

        //sending email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcom to Our website',
            text: `Welcom to Our website. Your account has been created with email id ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success: true});

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}
//------------------login ------------------
export const login = async (req,res) => {
    const {email , password } = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and Password are required'})
    }

    try {
        
        const user = await userModel.findOne({email});

        if(!user){
            return  res.json({success: false, message: 'Invalid email'})
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
          return  res.json({success: false, message: 'Invalid password'})  
        }

        const token = Jwt.sign({id: user._id},process.env.JWT_SECRET, {expiresIn: '7d'}); //mongodb store id

        res.cookie('token', token, {
            httpOnly: true,   // on live server
            secure: process.env.NODE_ENV === 'production',  //if run on local environment
            sameSite: process.env.NODE_ENV === 'production' ? 'none': 'strict',  //for deployment client and server on differnt domin
            maxAge: 7 * 24 * 60 * 60 * 1000  //cookie expire time in milisecond
        })

        return res.json({success: true});

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
    
}

//------------------log out-------------------

export const logout = async (req,res) => {

    try {
       res.clearCookie('token',{
            httpOnly: true,   // on live server
            secure: process.env.NODE_ENV === 'production',  //if run on local environment
            sameSite: process.env.NODE_ENV === 'production' ? 'none': 'strict',  //for deployment client and server on differnt domin
       }) 

       return res.json({success: true, message: "Logged Out"})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

//send verification OTP to the User's Email
export const sendVerifyOtp = async (req,res) => {
    console.log("req.body===", req.body)
    try {
        const {userId} = req.body;

       if (!userId) {
      return res.json({ success: false, message: "User ID not found" });
      }

       const user = await userModel.findById(userId);

       if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

       if(user.isAccountVerified){
        return res.json({success: false, message: "Account is already verified"})
       }

       const otp = String(Math.floor(100000 + Math.random()* 900000));

       user.verifyOtp = otp;
       user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000

       await user.save();

       const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verified OTP',
           //text: `Your OTP is ${otp}. Verify your account using this OTP.`
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
       }
       await transporter.sendMail(mailOption);

       res.json({success: true, message: 'Verification OTP Sent on Email'});
    } catch (error) {
        res.json({success: false , message: error.message});
    }
    
}

//verify email using otp
export const verifyEmail = async (req,res) => {
    const {userId, otp} = req.body;

    if(!userId || !otp){
        return res.json({success: false, message: 'Missing Details'});
    }

    try {
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({success: false, message: 'User not found'});
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({success: true, message: 'Email verified successfully'});

        

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
    
}

//check if user is authenticate
export const isAuthenticated = async (req,res) => {
    try {
        return res.json({success: true});  
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

//send password Reset Otp
export const sendResetOtp = async (req,res) => {
    const {email} = req.body;

    if(!email){
        return res.json({success: false, message: 'Email is Required'})
    }

    try {

        const user = await userModel.findOne({email});
        if(!user){
           return res.json({success: false, message: 'User not found'}) 
        }

        const otp = String(Math.floor(100000 + Math.random()* 900000));

       user.resetOtp = otp;
       user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000

       await user.save();

       const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            //text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password.`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
       };
       await transporter.sendMail(mailOption);

       return res.json({success: true, message: 'OTP sent to your email'})

    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

//Reset User Password

export const resetPassword = async (req,res) => {
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: 'Email, OTP and new Password are required'});
    }

    try {

        const user = await userModel.findOne({email});
        if(!user){
             return res.json({success: false, message: 'User not found'});
        }
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: 'Password has been reset successfully'});
        
    } catch (error) {
         return res.json({success: false, message: error.message});
    }
    
}