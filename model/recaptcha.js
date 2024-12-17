import env from "dotenv";
import axios from 'axios'; // For making HTTP requests
env.config();
const verifyCaptcha = async (req, res, next) => {
  const { recaptchaResponse } = req.body; // CAPTCHA token from the frontend
  const secretKey = process.env.GOOGLE_RECAPTCHA_SECRETKEY;
  try {
    // Verify CAPTCHA with Google's API
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
      params: {
        secret: secretKey, // Your secret key
        response: recaptchaResponse // CAPTCHA token
      }
    });

    if (response.data.success) {
      next(); // CAPTCHA is valid, continue processing the request
    } else {
      res.status(400).json({ message: 'CAPTCHA verification failed', errors: response.data['error-codes'] });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error verifying CAPTCHA', error: error.message });
  }
};

export default verifyCaptcha;
