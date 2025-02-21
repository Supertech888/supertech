const jwt = require("jsonwebtoken");
const User = require("../models/register");


exports.authen = async (req, res, next) => {
  const SECRET_KEY = process.env.SECRET_KEY
  try {

    //กำหนด token ที่่มากับ headers 
    let token = req.headers['authtoken']
    console.log(`⩇⩇:⩇⩇🚨  token :`, token);

  

    // ตรวจสอบว่ามี token หรือไม่
    if (!token) return res.status(400).send('Not confirm is Token')
  

    // ถ้ามี token ให้ทำการแปลง verify
    const decoded = jwt.verify(token, SECRET_KEY)

    // ✅ ตรวจสอบว่า Payload มี `user` หรือไม่
    if (decoded.user) {
      req.user = decoded.user;
    } else {
      // ✅ ถ้าไม่มี `user` ให้ map ข้อมูลใหม่
      req.user = {
        id: decoded.sub,
        username: decoded.username,
        role: decoded.role,
        permissions: decoded.permissions,
      };
    }
    next();
    console.log(5);
  } catch (error) {
    res.status(500).json({ error: "User is not Found!!" });
  }
};


exports.adminCheck = async (req, res, next) => {
  try {

    //console.log('log',req.user.username);
    const userAdmin = await User.findOne({ username: req.user.username }).select("-password").exec();
   
    if (userAdmin.role !== "admin") return res.status(404).send('Admin access denied!!!!!')

    next();
  } catch (error) {
    console.log(error);
    res.status(404).send('Admin access denied')

  }

}
