const {Router} = require("express")
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const adminRouter = Router();
const {adminModel,courseModel} = require("../db")
const {JWT_ADMIN_PASSWORD} = require("../config");
const { adminMiddleware } = require("../middleware/admin");

adminRouter.post('/signup',async function(req,res){
    try{
        
        const {email,password,firstName,lastName} = req.body;
        
        if (!email || !password || !firstName || !lastName) {
            return res.json({
                message: "All fields are required"
            });
        }

        const existingAdmin = await adminModel.findOne({ email });
        if (existingAdmin) {
            return res.json({
                message: "Email already registered"
            });
        }

        const hashedpassword= await bcrypt.hash(password,10);

        await adminModel.create({
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

adminRouter.post('/signin',async function(req,res){
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.json({
                message: "Email and password are required"
            });
        }

        const admin = await adminModel.findOne({
            email: email,
        });

        if (!admin) {
            return res.status(403).json({
                message: "Incorrect Credentials"
            });
        }

        const passwordMatch = await bcrypt.compare(password, admin.password);

        if (admin && passwordMatch) {
            const token = jwt.sign({
                id: admin._id
            }, JWT_ADMIN_PASSWORD);

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

adminRouter.post("/course",adminMiddleware,async function(req,res){
    const adminId = req.userId;

    const {title, description, imageUrl,price} = req.body;

    const course = await courseModel.create({
        title: title,
        description: description,
        imageUrl: imageUrl,
        price: price,
        creatorId: adminId
    })
    res.json({
        message: "Course created",
        courseId: course._id
    })
})

adminRouter.put("/course",adminMiddleware,async function(req,res){
    const adminId = req.userId;

    const {title, description, imageUrl,price,courseId} = req.body;
    
    const course = await courseModel.updateOne({
        _id: courseId,
        creatorId: adminId
    },{
        title: title,
        description: description,
        imageUrl: imageUrl,
        price: price,
    });
    res.json({
        message: "Course updated",
        courseId: courseId
    })
})

adminRouter.get("/course",adminMiddleware,async function(req,res){
    const adminId = req.userId;

    
    
    const courses = await courseModel.find({
        creatorId: adminId
    });
    res.json({
        message: "Course updated",
        courses
    })
})

module.exports={
    adminRouter: adminRouter
}