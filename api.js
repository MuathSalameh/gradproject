import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path, { parse } from "path";
import fs from "fs";
import multer from "multer";

env.config();
const app = express();
const port = 3000;
const saltRounds=10;
const db = new pg.Client({
    user: process.env.DATABASE_USER,
    host: "localhost",
    database: "EcoAct",
    password:process.env.DATABASE_PASSWORD,
    port: 5432,
  });

app.use(bodyParser.urlencoded({ extended: true }));
db.connect();

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      // Ensure that the directory exists
      const uploadDir = './uploads/';
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir);
      }
      cb(null, uploadDir);  // Set the directory for image uploads
    },
    filename: (req, file, cb) => {
      // Create a unique filename with the current timestamp
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
      // Accept images only
      const fileTypes = /jpeg|jpg|png/;
      const extName = fileTypes.test(path.extname(file.originalname).toLowerCase());
      const mimeType = fileTypes.test(file.mimetype);
  
      if (extName && mimeType) {
        cb(null, true);
      } else {
        cb(new Error('Only images are allowed!'));
      }
    }
});
//? User Registeration 
app.post("/api/auth/register",async(req,res)=>{
    const UserForRegister={
        "username" : req.body.username,
        "email" : req.body.email,
        "password" :  req.body.password 
        }
    try{
         const CheckUserExist = await db.query("SELECT * FROM Users WHERE Email=$1",[UserForRegister.email])
            if(CheckUserExist.rows.length<=0){
                  await bcrypt.hash(UserForRegister.password,saltRounds,async(err,hash)=>{
                        if(err){
                            console.log("Error Hashing password",err);
                        }
                        else{
                            const result = await db.query("INSERT INTO users (username, email, password_hash) VALUES ($1,$2,$3) RETURNING * ", 
                                        [UserForRegister.username,UserForRegister.email,hash] ) ;
                            const UserInfo = result.rows[0];
                            const User={ id: UserInfo.user_id, username: UserInfo.username }; 
                                if(User){
                                    const token = jwt.sign(User, process.env.ACCESS_TOKEN_KEY);
                                    res.status(201).json({ message: 'User registered successfully' , User : result.rows ,token});
                                }
                            }
                        });
                }
            else{
                    res.status(404).json({message:"User already exists"});
                 }
    }
    catch(err){
        console.log(err);
        res.status(500).json({ error: 'Registration failed' });
    }
});
//? User Login
app.post("/api/auth/login", async(req ,res)=>{
const UserForLogin = {
    "email" : req.body.email ,
    "password" : req.body.password
}
    try{
        const result = await db.query("SELECT * FROM users WHERE email=$1", [UserForLogin.email]);
        const UserInfo = result.rows[0];
        const User={ id: UserInfo.user_id, username: UserInfo.username };
        if(User && await bcrypt.compare(UserForLogin.password, UserInfo.password_hash)){
            const token = jwt.sign(User, process.env.ACCESS_TOKEN_KEY);
            res.status(200).json({ message: 'Logged in successfully', token });
        }
        else{
            res.status(401).json({ error: 'Invalid credentials' });
        }
    }
    catch(err){
        console.log(err);
        res.status(500).json({ error: 'Login failed' });
    }

});
//? post new report 
app.post("/api/add/report",checkAuth,upload.array('reportImg',3), async(req ,res)=>{
    const UserId=req.user.id;
    const Report = {
        "issueType" : req.body.issueType ,
        "description" : req.body.description ,
    }
    const reportLocation = `POINT(${req.body.longitude} ${req.body.latitude})`;
    const file = req.files;
    const mainImagePath=file.length>0?file[0].path:null;
        try{
            const insertResult=await db.query("INSERT INTO reports (user_id, issue_type_id, description,main_image_url,location) VALUES ($1,(SELECT issue_type_id FROM issue_types WHERE name = $2), $3,$4,$5) RETURNING *;" ,
                [UserId,Report.issueType,Report.description,mainImagePath,reportLocation]);
                const newReportInfo = insertResult.rows[0];
                if(file.length>0){
                    file.forEach(async (element) => {
                        await db.query("INSERT INTO images (report_id,image_path)VALUES($1,$2) ",[newReportInfo.id,element.path]);
                    });
                }
            res.status(200).json({ Message:'report added successfully' , report : insertResult.rows[0]});
        }
        catch(err){
            res.status(500).json({ error: 'Error While adding report' });
        }
});
//? put(edit) a report
app.put("/api/edit/report/:id", checkAuth , async(req ,res)=>{
    const reportId = parseInt(req.params.id);
    const UserId=req.user.id;
    const Report = {
        "issueType" : req.body.issueType ,
        "description" : req.body.description 
    };
    const reportLocation = `POINT(${req.body.longitude} ${req.body.latitude})`;
        try{
                const updateResult = await db.query("UPDATE reports SET issue_type_id =(SELECT issue_type_id FROM issue_types WHERE name=$1) , description=$2 ,location =$3 WHERE report_id = $4 AND user_id= $5 RETURNING *;",
                [Report.issueType,Report.description,reportLocation,reportId,UserId]
            );
            if(updateResult.length>0)
            res.status(200).json({ Message:'report updated successfully' , report : updateResult.rows[0]});
            else{
                res.status(404).json({ Message:'report doesn\'t exist or doesn\'t belong to you'});
            }
        }
        catch(err){
            res.status(500).json({ error: 'Error While updating report' });
        }
});
//? Delete a report
app.delete("/api/delete/report/:id",checkAuth,async(req ,res)=>{
    const reportId=parseInt(req.params.id);
    const UserId=req.user.id;
        try{
             await db.query("DELETE FROM reports WHERE report_id=$1 AND user_id=$2 ;" ,[reportId,UserId]);
             res.status(200).json({ Message:`report with ID ${reportId} has been deleted successfully.`}) 
        }
        catch(err){
            res.status(500).json({ error: 'Error While deleting report' });
        }
});
//? get all reports with filtering by issue-type
app.get("/api/reports",async(req ,res)=>{
    const issuetype =req.query.issuetype || "";
    try{
        if(issuetype){
            const filterResult = await db.query("SELECT report_id ,issue_type_id , description ,main_image_url ,ST_X(location::GEOMETRY) longitude, ST_Y(location::GEOMETRY) latitude, created_at report_created_at FROM reports WHERE issue_type_id=(SELECT issue_type_id FROM issue_types WHERE name = $1);",[issuetype]);
            res.status(200).json(filterResult.rows); 
        }
        else{
            const result = await db.query("SELECT report_id ,issue_type_id , description ,main_image_url ,ST_X(location::GEOMETRY) longitude, ST_Y(location::GEOMETRY) latitude, created_at report_created_at FROM reports;");
            res.status(200).json(result.rows); 
        }
    }
    catch(err){
        res.status(401).json({ error: 'error getting reports '});
        console.log(err)
    }
});
//? get a single report
app.get("/api/reports/:id",async(req ,res)=>{
    const reportId=parseInt(req.params.id);
    try{
        const result = await db.query("SELECT report_id ,issue_type_id , description ,main_image_url ,ST_X(location::GEOMETRY) longitude, ST_Y(location::GEOMETRY) latitude, created_at report_created_at FROM reports WHERE report_id=$1;" ,[reportId]);
        const reportImages =await db.query("SELECT * FROM images WHERE report_id=$1;" ,[reportId]);
        res.status(200).json({report : result.rows[0] , images : reportImages.rows}); 
    }
    catch(err){
        res.status(401).json({ error: 'error while fetching the report '});
    }
});
//? get hotspot areas (manage_hotsopt_clusters())
app.get("/api/hotspot-areas",async(req ,res)=>{
    try{
        const result = await db.query("SELECT out_cluster_id cluster_id ,ST_X(hotspot_center::GEOMETRY) longitude, ST_Y(hotspot_center::GEOMETRY)latitude,issue_count FROM manage_hotspot_clusters();");
        res.status(200).json(result.rows); 
    }
    catch(err){
        res.status(401).json({ error: 'error getting hotspot area'});
    }
});
//? get user profile 
app.get("/api/user/info",checkAuth, async(req ,res)=>{
    const userID = req.user.id;
    try{
        const User = await db.query("SELECT u.username ,u.email ,u.created_at profile_created_at FROM users u WHERE u.user_id=$1;" ,[userID]);
        const Reports =await db.query("SELECT report_id , issue_type_id,description ,main_image_url , ST_X(location::GEOMETRY) longitude, ST_Y(location::GEOMETRY) latitude,created_at report_created_at FROM reports WHERE user_id=$1;" ,[userID]);
        res.status(200).json({ User: User.rows[0] , Reports : Reports.rows}); 
    }
    catch(err){
        res.status(401).json({ error: 'Invalid Token'});
    }
});
//? edit user profile 
app.put("/api/user/edit", checkAuth , async(req ,res)=>{
    const UserForEdit={
        "username" : req.body.username,
        "email" : req.body.email
     }
    const userID = req.user.id;
    try{
        const User = await db.query("UPDATE users SET username =$1 , email=$2 WHERE user_id=$3 RETURNING *;" ,[UserForEdit.username,UserForEdit.email,userID]);
        res.status(200).json({message:"User updated successfully" ,User:User.rows[0]}); 
    }
    catch(err){
        res.status(401).json({ error: 'error editing user'});
        console.log(UserForEdit)
    }
});

function checkAuth(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
            if(!token){
                return res.status(403).json({ message: 'Not authenticated' });
            }
            try{
                    jwt.verify(token, process.env.ACCESS_TOKEN_KEY , (err,user)=>{
                    if(err){
                       return  res.status(401).json({ message: 'Invalid token' })
                    }; 
                     req.user =user;
                    next();
                });
            }
            catch(err){
                return res.status(401).json({ message: 'Invalid token' });
            }
}
app.listen(port,()=>{
    console.log(`app running on port ${port}`)
})