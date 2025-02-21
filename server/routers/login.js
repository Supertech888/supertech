const express = require("express");
const router = express.Router();
const { logged, currentUser, loggedLine, loggedFacebook ,externalLogin} = require("../controllers/authController");
const { authen, adminCheck } = require('../middleware/auth')


router.post("/login", logged);

router.post("/auth/external-login", externalLogin); // ✅ เพิ่ม API สำหรับ SSO

router.post("/login-line", loggedLine);
router.post("/login-facebook", loggedFacebook);




router.post('/current-user', authen, currentUser)
router.post('/current-admin', authen, adminCheck, currentUser)

// router.post("/login1",authen, (req, res)  => {
//         res.send('5555')
// });







module.exports = router;
