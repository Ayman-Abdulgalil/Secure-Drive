import { useState } from "react";
import { Box, Card, TextField, Button, Typography, Alert } from "@mui/material";
import { useNavigate } from "react-router-dom";
import Logo from "../assets/logo.svg";

function Signup() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        name: "",
        email: "",
        password: "",
        confirmPassword: ""
    });
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSignup = async () => {
        setError("");
        setSuccess("");

        // Validation
        if (!formData.name || !formData.email || !formData.password) {
            setError("Please fill in all fields");
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            setError("Passwords do not match");
            return;
        }

        if (formData.password.length < 8) {
            setError("Password must be at least 8 characters");
            return;
        }

        setLoading(true);

        try {
            const response = await fetch("http://localhost:8000/api/v1/auth/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    name: formData.name,
                    email: formData.email,
                    password: formData.password
                }),
            });

            const data = await response.json();

            if (response.ok) {
                setSuccess("Account created! Check your email to verify your account.");
                // Clear form
                setFormData({
                    name: "",
                    email: "",
                    password: "",
                    confirmPassword: ""
                });
                // Redirect to login after 3 seconds
                setTimeout(() => {
                    navigate("/login");
                }, 3000);
            } else {
                setError(data.detail || "Signup failed. Please try again.");
            }
        } catch (err) {
            setError("Network error. Please check if the backend is running.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <Card
            sx={{
                width: 380,
                padding: 7,
                borderRadius: 3,
                backgroundColor: "#ffffff",
                boxShadow: "0px 10px 40px rgba(0,0,0,0.3)",
                textAlign: "center"
            }}>
            {/* Title */}
            <Box display="flex" alignItems="center" flexDirection="column" mb={2}>
                <img src={Logo} alt="Secure Drive logo" style={{ width: 150, height: 150, marginBottom: 6 }} />
                <Typography variant="h3" fontWeight={700} lineHeight={1.1} sx={{ fontSize: "1.8rem" }}>
                    Secure Drive
                </Typography>
            </Box>
            <Box display="flex" alignItems="center" flexDirection="column" mb={2}>
                <Typography variant="h3" fontWeight={700} lineHeight={1.1} sx={{ fontSize: "1.3rem" }}>
                    Create Account
                </Typography>
            </Box>

            {/* Error/Success Messages */}
            {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                </Alert>
            )}
            {success && (
                <Alert severity="success" sx={{ mb: 2 }}>
                    {success}
                </Alert>
            )}

            {/* Name */}
            <Box mb={2} textAlign="left">
                <Typography variant="body2" mb={0.5}>
                    Name
                </Typography>
                <TextField 
                    fullWidth 
                    size="small" 
                    placeholder="Enter your name"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                />
            </Box>

            {/* Email */}
            <Box mb={2} textAlign="left">
                <Typography variant="body2" mb={0.5}>
                    Email
                </Typography>
                <TextField 
                    fullWidth 
                    size="small" 
                    placeholder="Enter your email"
                    name="email"
                    type="email"
                    value={formData.email}
                    onChange={handleChange}
                />
            </Box>

            {/* Password */}
            <Box mb={2} textAlign="left">
                <Typography variant="body2" mb={0.5}>
                    Password
                </Typography>
                <TextField 
                    fullWidth 
                    size="small" 
                    type="password" 
                    placeholder="Create a password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                />
            </Box>

            {/* Confirm Password */}
            <Box mb={3} textAlign="left">
                <Typography variant="body2" mb={0.5}>
                    Confirm Password
                </Typography>
                <TextField 
                    fullWidth 
                    size="small" 
                    type="password" 
                    placeholder="Confirm your password"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                />
            </Box>

            {/* Signup button */}
            <Button 
                fullWidth 
                variant="contained"
                onClick={handleSignup}
                disabled={loading}
                sx={{
                    backgroundColor: "#4F46E5",
                    borderRadius: 2,
                    textTransform: "none",
                    fontWeight: 500,
                    py: 1,
                    mb: 2
                }}>
                {loading ? "Creating Account..." : "Sign Up"}
            </Button>

            {/* Switch to login */}
            <Typography variant="body2">
                Already have an account?{" "}
                <span style={{ color: "#4F46E5", cursor: "pointer" }} onClick={() => navigate("/login")}>
                    Login
                </span>
            </Typography>
        </Card>
    );
}

export default Signup;