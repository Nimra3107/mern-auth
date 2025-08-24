import userModel from "../models/userModel.js";

export const getUserData = async (req,res) => {

    try {

        //const {userId} = req.body;
        const userId = req.user.id;
        //const userId = req.user?.id;

        const user = await userModel.findById(userId);

        if(!user){
            return res.json({success: false, message: 'User not found'});
        }
        console.log("user", user);
        

        res.json({
            success: true, 
            userData: {
                name: user.name,
                userId: user._id,
                email: user.email,
                isAccountVerified: user.isAccountVerified
            }
        });
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
    
}