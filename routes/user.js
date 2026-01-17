const {Router} = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { userModel ,purchaseModel, courseModel} = require("../db");
const {JWT_USER_PASSWORD} = require("../config");
const { userMiddleware } = require("../middleware/user");

const userRouter=Router();

userRouter.post('/signup',async function(req,res){
    try{
        
        const {email,password,firstName,lastName} = req.body;
        
        if (!email || !password || !firstName || !lastName) {
            return res.json({
                message: "All fields are required"
            });
        }

        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.json({
                message: "Email already registered"
            });
        }

        const hashedpassword= await bcrypt.hash(password,10);

        await userModel.create({
            email: email,
            password: hashedpassword,
            firstName: firstName,
            lastName: lastName
        })

        res.json({
            message:"Signup Succeeded"
        })

    }catch(err){

        console.log(err);
        res.status(500).json({
            message:"Internal Server Error"
        })

    }
    
});
userRouter.post('/signin', async function (req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.json({
                message: "Email and password are required"
            });
        }

        const user = await userModel.findOne({
            email: email,
        });

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (user && passwordMatch) {
            const token = jwt.sign({
                id: user._id
            }, JWT_USER_PASSWORD);

            res.json({
                token: token
            });
        } else {
            res.status(403).json({
                message: "Incorrect Credentials"
            });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Internal Server Error"
        });
    }
});


userRouter.get('/purchases',userMiddleware,async function(req,res){
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId
    });
    const coursedata = await courseModel.find({
        _id: { $in: purchases.map(x=> x.courseId)}
    });
    res.json({
        purchases,
        coursedata
    })
});

module.exports = {
    userRouter: userRouter
}