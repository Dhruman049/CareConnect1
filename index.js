// index.js
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongo');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const flash = require('connect-flash');
const moment = require('moment');
const { body, validationResult } = require('express-validator');
const app = express();

// MongoDB Connection
const mongoUrl = 'mongodb://localhost:27017/CareConnectDB'; // Replace 'yourDBName' with your actual database name

mongoose.connect(mongoUrl)
    .then(() => console.log("MongoDB Connected"))
    .catch((err) => console.log(err));

// Session Store Configuration
const store = MongoDBStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions' // Change collection name if needed
});
async function hashPassword(password) {
    const saltRounds = 12;  // Consider increasing this value (e.g., 12 or 14)
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
}
// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
// Middleware for session and flash
app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: false,
    store: store
  
}));
app.use(flash()); // Add connect-flash middleware
// Middleware for making flash messages accessible in views
app.use((req, res, next) => {
    res.locals.successMessage = req.flash('success'); // Make flash messages available to EJS views
    res.locals.errorMessage = req.flash('error');
    next();
});


app.use(express.json()); 

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const UserSchema = new mongoose.Schema({
    user_FirstName: { type: String, required: true },
    user_LastName: { type: String, required: true },
    user_Email: { type: String, unique: true, required: true },
    user_Address: String,
    user_Password: { type: String, required: true },
    user_PhoneNo: String,
    user_DOB: Date,
    user_Role: { type: String, enum: ['Patient', 'Specialist', 'Admin'], required: true },
    user_SpecialistType: String,
    assignedSpecialistId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Users', // Ensure this references the correct model
        default: null
    }
});

const User = mongoose.model('Users', UserSchema);

// Registration Route
app.get('/register', (req, res) => {
    const role = req.session.role || null; // Get the role from the session, or set to null if not logged in
    res.render('register', { role });
});
// Registration Route
app.get('/about', (req, res) => {
    const role = req.session.role || null; 
    const loggedInPatientId = req.session.loggedInPatientId || null; // Get the patient ID from the session if exists
    const loggedInSpecialistId = req.session.loggedInSpecialistId || null;
    res.render('about', { role, loggedInPatientId,loggedInSpecialistId }); // Pass it to the EJS template
});
app.get('/services', (req, res) => {
    const role = req.session.role || null; 
    const loggedInPatientId = req.session.loggedInPatientId || null; // Get the patient ID from the session if exists
    const loggedInSpecialistId = req.session.loggedInSpecialistId || null;
    res.render('services', { role, loggedInPatientId,loggedInSpecialistId }); 
});




// Route for the homepage
app.get('/', (req, res) => {
    res.render('home', {
        title: 'Home',
        role: req.session.role,
        loggedInPatientId: req.session.userId,
        loggedInSpecialistId: req.session.userId
    });
});

// Registration route
app.post('/register', [
    // Validation rules
    body('firstName').trim().notEmpty().withMessage('First Name is required.'),
    body('lastName').trim().notEmpty().withMessage('Last Name is required.'),
    body('email').isEmail().withMessage('Please enter a valid email address.'),
    body('address').trim().notEmpty().withMessage('Address is required.'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
    body('phoneNo').optional().isNumeric().withMessage('Phone number must be numeric.'),
    body('dob').custom(value => {
        const today = moment().endOf('day');
        const maxDOB = moment().subtract(120, 'years').endOf('day');
        const selectedDOB = moment(value);
        if (selectedDOB.isAfter(today) || selectedDOB.isBefore(maxDOB)) {
            throw new Error('Please enter a valid date of birth. It must be in the past and not more than 120 years ago.');
        }
        return true;
    })
], async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Collect error messages
        const errorMessages = errors.array().map(error => error.msg);
        req.flash('error', errorMessages.join(' '));
        return res.redirect('/register');
    }

    const {
        firstName,
        lastName,
        email,
        address,
        password,
        phoneNo,
        dob,
        role,
        specialistType,
        specialistId
    } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ user_Email: email });
    if (existingUser) {
        req.flash('error', 'The email address you entered is already associated with an account.');
        return res.redirect('/register');
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create new user
    const user = new User({
        user_FirstName: firstName,
        user_LastName: lastName,
        user_Email: email,
        user_Address: address,
        user_Password: hashedPassword,
        user_PhoneNo: phoneNo,
        user_DOB: dob,
        user_Role: role,
        assignedSpecialistId: specialistId ? specialistId : null
    });

    try {
        await user.save();
        req.flash('success', 'Registration successful! You can now log in.');
        res.redirect('/login');
    } catch (error) {
        console.error("Error saving user:", error);
        req.flash('error', 'Registration failed: ' + error.message);
        res.redirect('/register');
    }
});

// Login route
app.get('/login', (req, res) => {
    // Use already set locals instead of calling req.flash again
    res.render('login', {
        successMessage: res.locals.successMessage,
        errorMessage: res.locals.errorMessage
    });
});


// Login route
app.post('/login', [
    // Validation rules
    body('email').isEmail().withMessage('Please enter a valid email address.'),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Collect error messages
        const errorMessages = errors.array().map(error => error.msg);
        req.flash('error', errorMessages.join(' '));
        return res.redirect('/login');
    }

    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ user_Email: email });
    if (!user) {
        req.flash('error', 'Invalid credentials'); // Error flash message
        return res.redirect('/login');
    }

    // Check password using bcrypt
    const isMatch = await bcrypt.compare(password, user.user_Password);
    if (!isMatch) {
        req.flash('error', 'Invalid credentials'); // Error flash message
        return res.redirect('/login');
    }

    // Successful login
    req.session.userId = user._id;
    req.session.role = user.user_Role; // Store user role in session
    req.flash('success', 'Login successful!'); // Success flash message

    // Redirect based on user role
    if (user.user_Role === 'Specialist') {
        return res.redirect('/specialist/dashboard');
    } else if (user.user_Role === 'Admin') {
        return res.redirect('/admin/dashboard');
    } else {
        return res.redirect('/dashboard');
    }
});
// Dashboard Route
app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        const userId = req.session.userId; // Get logged-in user ID
        const user = await User.findById(userId); // Fetch user data

        if (!user) {
            return res.redirect('/login'); // If user not found, redirect to login
        }

        const userName = `${user.user_FirstName} ${user.user_LastName}`; // Create full name
        res.render('dashboard', {
            role: req.session.role,
            loggedInPatientId: userId,
            userName // Pass userName to the view
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to fetch user data');
    }
});


// Admin Dashboard Route
app.get('/admin/dashboard', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if user is not logged in or is not an admin
    }

    try {
        const appointments = await Appointment.find()
            .populate('patientId')
            .populate('specialistId');

        // Directly use the flash messages in locals (already set in middleware above)
        const successMessage = req.flash('success');
        const errorMessage = req.flash('error');

        res.render('admin-dashboard', {
            appointments,
            successMessage, // Pass success messages to view
            errorMessage,   // Pass error messages to view
            role: req.session.role
        });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to fetch appointments'); // Set error message
        res.redirect('/admin/dashboard'); // Redirect to self to show error
    }
});

// Route to delete an appointment
app.post('/admin/appointments/:id/delete', async (req, res) => {
    const appointmentId = req.params.id;

    try {
        const appointment = await Appointment.findById(appointmentId);
        if (!appointment) {
            req.flash('error', 'Appointment not found');
            return res.redirect('/admin/dashboard');
        }

        await Appointment.findByIdAndDelete(appointmentId);
        req.flash('success', 'Appointment deleted successfully!'); // Set success message

        return res.redirect('/admin/dashboard'); // Redirect to the dashboard
    } catch (error) {
        console.error('Error deleting appointment:', error);
        req.flash('error', 'Failed to delete appointment'); // Set error message
        return res.redirect('/admin/dashboard'); // Redirect to the dashboard
    }
});


// Appointment Schema
const AppointmentSchema = new mongoose.Schema({
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    specialistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    user_Name: { type: String, required: true }, // User name booking the appointment
    Appointments_availability: { type: String, default: "Available" }, // Availability status
    Appointments_date: { type: Date, required: true }, // Appointment date
    Appointments_confirmation: { type: String, enum: ['Pending', 'Confirmed', 'Canceled'], default: 'Pending' }, // Confirmation status
    Appointments_type: { type: String, enum: ['Video Consultation', 'In-Person'], required: true }, // Type of appointment
    Appointments_status: { type: String, enum: ['Scheduled', 'Completed', 'Canceled'], default: 'Scheduled' },
    notes: { type: String },
    videoLink: { type: String }

});

const Appointment = mongoose.model('Appointments', AppointmentSchema);


// New appointment page route
app.get('/appointments/new', async (req, res) => {
    console.log("Accessing new appointment page");
    if (!req.session.userId) {
        console.log("User is not logged in, redirecting to login");
        return res.redirect('/login');
    }

    const specialists = await User.find({ user_Role: 'Specialist' });
    // Fetch existing appointments for each specialist for the next 7 days, limiting displayed time slots.
    const now = new Date();
    const availableSlots = {}; // To store available slots for each specialist

    for (const specialist of specialists) {
        availableSlots[specialist._id] = []; // Initialize slots for each specialist

        // Loop through the next 7 days to find available slots
        for (let hour = 9; hour < 19; hour++) { // Assuming working hours from 9 AM to 7 PM
            const slotDate = new Date();
            slotDate.setHours(hour, 0, 0, 0);

            // Check if there's an appointment booked at this time
            const existingAppointment = await Appointment.findOne({
                specialistId: specialist._id,
                Appointments_date: {
                    $gte: slotDate,
                    $lt: new Date(slotDate.getTime() + 45 * 60 * 1000) // Next 45 minutes
                }
            });

            if (!existingAppointment) {
                availableSlots[specialist._id].push(slotDate);
            }
        }
    }

    // Render the new appointment page with available slots
    res.render('new-appointment', { specialists, availableSlots, role: req.session.role, loggedInPatientId: req.session.userId });
});


app.post('/admin/appointments/:id', async (req, res) => {
    const appointmentId = req.params.id;
    const { status, specialistId } = req.body; // Added specialistId to the destructuring

    try {
        const appointment = await Appointment.findById(appointmentId)
            .populate('patientId')
            .populate('specialistId');

        if (!appointment) {
            req.flash('error', 'Appointment not found');
            return res.redirect('/admin/dashboard');
        }

        // Update the appointment confirmation status
        appointment.Appointments_confirmation = status;

        // Update the appointment status based on confirmation
        if (status === 'Confirmed') {
            appointment.Appointments_status = 'Completed'; // Set to Completed if confirmed

            // Assign specialist to patient if a specialist is selected
            if (specialistId) {
                const patient = await User.findById(appointment.patientId._id);
                
                if (patient) {
                    // Update patient's assigned specialist
                    patient.assignedSpecialistId = specialistId;
                    await patient.save();

                    // Create a notification about specialist assignment
                    const specialistAssignmentNotification = new Notification({
                        notification_id: Date.now() + 2,
                        user_id: appointment.patientId._id,
                        specialist_id: specialistId,
                        notification_message: `You have been assigned a specialist for your confirmed appointment.`,
                        notification_type: 'Specialist Assignment',
                        notification_status: 'Sent'
                    });
                    await specialistAssignmentNotification.save();
                }
            }

            // Generate a video link only for video consultations
            if (appointment.Appointments_type === 'Video Consultation') {
                appointment.videoLink = `https://meet.example.com/${appointmentId}`; // Placeholder link

                // Notify both patient and specialist
                const notificationMessage = `Your appointment with ${appointment.patientId.user_FirstName} ${appointment.patientId.user_LastName} has been confirmed. Join the video call at: ${appointment.videoLink}`;
                
                const patientNotification = new Notification({
                    notification_id: Date.now(),
                    user_id: appointment.patientId._id,
                    specialist_id: appointment.specialistId._id,
                    notification_message: notificationMessage,
                    notification_type: 'Appointment Confirmation',
                    notification_status: 'Sent'
                });

                const specialistNotification = new Notification({
                    notification_id: Date.now() + 1, // Ensure unique ID
                    user_id: appointment.specialistId._id,
                    specialist_id: appointment.specialistId._id,
                    notification_message: notificationMessage,
                    notification_type: 'Appointment Confirmation',
                    notification_status: 'Sent'
                });

                await patientNotification.save();
                await specialistNotification.save();
            }
        } else if (status === 'Canceled') {
            appointment.Appointments_status = 'Canceled'; // Automatically set to Canceled
        } else {
            appointment.Appointments_status = 'Scheduled'; // Default to Scheduled if pending
        }

        await appointment.save();

        req.flash('success', 'Appointment status updated successfully');
        return res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error updating appointment:', error);
        req.flash('error', 'Failed to update appointment status');
        return res.redirect('/admin/dashboard');
    }
});


// Handle new appointment submission
app.post('/appointments', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const { specialistId, appointmentDate, time, appointmentType, notes } = req.body;

    // Regular Expressions for validation
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/; // YYYY-MM-DD format
    const timeRegex = /^(0?[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/; // HH:mm format (24-hour)

    // Validate required fields
    if (!specialistId || !appointmentDate || !time || !appointmentType) {
        req.flash('error', "All fields must be filled out.");
        return res.redirect('/appointments/new');
    }

    // Validate date and time formats
    if (!dateRegex.test(appointmentDate)) {
        req.flash('error', "Appointment date must be in YYYY-MM-DD format.");
        return res.redirect('/appointments/new');
    }

    if (!timeRegex.test(time)) {
        req.flash('error', "Time must be in HH:mm format.");
        return res.redirect('/appointments/new');
    }

    const appointmentDateTime = new Date(`${appointmentDate}T${time}`);

    // Check if the appointment date-time is valid
    if (isNaN(appointmentDateTime.getTime())) {
        req.flash('error', "Invalid date or time.");
        return res.redirect('/appointments/new');
    }

    try {
        // Check for existing appointments
        const existingAppointment = await Appointment.findOne({
            specialistId: specialistId,
            Appointments_date: {
                $gte: appointmentDateTime,
                $lt: new Date(appointmentDateTime.getTime() + 45 * 60 * 1000) // 45 minutes later
            }
        });

        if (existingAppointment) {
            req.flash('error', "This time slot is already booked. Please choose a different slot.");
            return res.redirect('/appointments/new');
        }

        // Fetch user information to create the appointment
        const user = await User.findById(req.session.userId);
        const appointment = new Appointment({
            patientId: req.session.userId,
            specialistId,
            user_Name: `${user.user_FirstName} ${user.user_LastName}`,
            Appointments_availability: "Available",
            Appointments_date: appointmentDateTime,
            Appointments_confirmation: "Pending",
            Appointments_type: appointmentType,
            notes: notes || ''
        });

        await appointment.save();

        // Flash success message after booking the appointment
        req.flash('success', "Appointment booked successfully!");
        return res.redirect('/appointments/new');
    } catch (err) {
        console.error("Error creating appointment:", err);
        req.flash('error', "An error occurred while creating the appointment.");
        return res.redirect('/appointments/new');
    }
});


// Appointments listing route
app.get('/appointments', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        const appointments = await Appointment.find({ patientId: req.session.userId }).populate('specialistId');
        res.render('appointments', { appointments, role: req.session.role, loggedInPatientId: req.session.userId });
    } catch (err) {
        console.error(err);
        req.flash('error', "An error occurred while fetching appointments.");
        return res.redirect('/appointments'); // Redirect to show error message
    }

    console.log('User Role:', req.session.role);
});



//Labreport Schema

const labReportSchema = new mongoose.Schema({
    LabReports_id: { type: Number, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    Specialist_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Specialists', required: true },
    LabReports_File: { type: String, required: true }, // Could be a path or URL where the file is stored
    LabReports_Date: { type: Date, default: Date.now },
    LabReports_Notes: { type: String },
    notifications: [{
        createdAt: { type: Date, default: Date.now },
        message: String,
        read: { type: Boolean, default: false }
    }]
});

const LabReport = mongoose.model('LabReport', labReportSchema);

// Setup multer for file upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads/'); // Ensure this folder exists
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|pdf/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Error: File type not supported!'));
    }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Route to handle lab report upload
app.post('/specialist/upload-lab-report', upload.single('labReportFile'), async (req, res) => {
    const { userId, notes } = req.body;

    // Check if the file was uploaded
    if (!req.file) {
        req.flash('error', 'Please upload a valid file.');
        return res.redirect('/specialist/upload-lab-report'); // Redirect to the upload page
    }

    const newLabReport = new LabReport({
        LabReports_id: Date.now(),
        user_id: userId,
        Specialist_id: req.session.userId,
        LabReports_File: req.file.path,
        LabReports_Notes: notes,
    });

    try {
        await newLabReport.save();

        // Notify the patient
        const notification = new Notification({
            notification_id: Date.now(),
            user_id: userId,
            specialist_id: req.session.userId,
            notification_message: `Your specialist has uploaded a new lab report.`,
            notification_type: 'New Report'
        });

        await notification.save();

        req.flash('success', 'Lab report uploaded successfully!');
        return res.redirect('/specialist/upload-lab-report'); // Redirect after successful upload
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to upload lab report: ' + error.message);
        return res.redirect('/specialist/upload-lab-report'); // Redirect back on error
    }
});

// Route to render the lab report upload form
app.get('/specialist/upload-lab-report', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Specialist') {
        req.flash('error', 'You must be logged in as a specialist to access this page.');
        return res.redirect('/login'); // Redirect if not logged in or not a specialist
    }

    // Fetch patients assigned to the specialist
    try {
        const patients = await User.find({ assignedSpecialistId: req.session.userId });
        res.render('upload-lab-report', {
            patients,
            role: req.session.role,
            loggedInSpecialistId: req.session.userId
        });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to fetch patients for lab report upload.');
        res.redirect('/specialist/dashboard');
    }
});

app.get('/specialist/view-patients-reports', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect if not authenticated
    }

    const specialistId = req.session.userId;
    const role = req.session.role; // Assuming role is stored in the session

    try {
        const labReports = await LabReport.find({ Specialist_id: specialistId }).populate('user_id'); // Ensure user_id is populated

        // Create unique patients with their first and last names
        const patients = labReports
            .map(report => ({
                id: report.user_id._id,
                name: `${report.user_id.user_FirstName} ${report.user_id.user_LastName}` || 'Unknown Patient', // Combine first and last names
                reportCount: labReports.filter(r => r.user_id._id.equals(report.user_id._id)).length
            }))
            .filter((thing, i, arr) => arr.findIndex(t => t.id === thing.id) === i);  // Unique patients

        // Pass both the 'role' and 'loggedInSpecialistId' to the EJS template
        res.render('specialist-patients-reports', { patients, role, loggedInSpecialistId: specialistId });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to retrieve patients.');
    }
});

app.get('/patient/lab-reports', async (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.redirect('/login');
    }

    try {
        const labReports = await LabReport.find({ user_id: userId }).sort({ LabReports_id: -1 });

        const role = req.session.role || 'Patient';
        const loggedInPatientId = userId;
        const loggedInSpecialistId = req.session.specialistId || null;

        // Pass variables to EJS
        res.render('patient-lab-reports', { labReports, role, loggedInPatientId, loggedInSpecialistId });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to retrieve lab reports');
    }
});


// Route to handle sending messages
app.post('/specialist/send-message', async (req, res) => {
    const { receiverId, messageContent } = req.body;

    const newMessage = new Message({
        sender_id: req.session.userId,
        receiver_id: receiverId,
        message_content: messageContent
    });

    try {
        await newMessage.save();

        // Create a notification for the patient
        const notification = new Notification({
            notification_id: Date.now(),
            user_id: receiverId,
            specialist_id: req.session.userId,
            notification_message: `You have received a new message from your specialist.`,
            notification_type: 'New Message'
        });

        await notification.save();
        req.flash('success', 'Message sent successfully!'); // Set success message
        res.redirect('/specialist/messages'); // Redirect to messages page
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to send message. Please try again.'); // Set error message
        res.redirect('/specialist/send-message'); // Redirect back to the send message page
    }
});


// Specialist Dashboard Route
app.get('/specialist/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    // Fetch the user's role and ID from the session or database
    const userRole = req.session.role; // Assuming role is stored in the session
    const loggedInSpecialistId = req.session.specialistId; // Assuming the specialist ID is stored in the session

    // Render the dashboard and pass the 'role' and 'loggedInSpecialistId' variables to the view
    res.render('specialist-dashboard', { role: userRole, loggedInSpecialistId });
});

const messageSchema = new mongoose.Schema({
    sender_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true }, // Sender ID
    receiver_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true }, // Receiver ID
    message_content: { type: String, required: true }, // Message content
    message_date: { type: Date, default: Date.now }, // Message timestamp
    reply_to: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' } // Reference to the original message (if replying)
});

const Message = mongoose.model('Message', messageSchema);

// Route to handle sending messages from specialist to patient
app.post('/specialist/send-message', async (req, res) => {
    const { receiverId, messageContent } = req.body;

    const newMessage = new Message({
        sender_id: req.session.userId,  // Specialist ID from session
        receiver_id: receiverId,
        message_content: messageContent
    });

    try {
        await newMessage.save();

        // Create a notification for the patient (optional)
        const notification = new Notification({
            notification_id: Date.now(),
            user_id: receiverId, // Patient ID
            specialist_id: req.session.userId, // Specialist ID
            notification_message: `You have received a new message from your specialist.`,
            notification_type: 'New Message'
        });

        await notification.save();
        res.redirect('/specialist/message'); // Redirect to the specialist dashboard after sending the message
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to send message');
    }
});


// Route to display the send message page for specialists
app.get('/specialist/send-message', async (req, res) => {
    // Ensure the user is logged in and has the role of Specialist
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login'); // Redirect if not logged in or not a specialist
    }

    try {
        const specialistId = req.session.userId; // Get logged-in specialist ID

        // Fetch patients assigned to the specialist
        const patients = await User.find({ assignedSpecialistId: specialistId });

        // Check if patients were found
        if (!patients.length) {
            return res.render('send-message', {
                patients: [], // Pass an empty array if no patients found
                role: req.session.role,
                loggedInSpecialistId: specialistId,
                message: 'No patients assigned to you currently.' // Optional message
            });
        }

        // Render the send-message page with the list of patients
        res.render('send-message', {
            patients,
            role: req.session.role,
            loggedInSpecialistId: specialistId
        });
    } catch (error) {
        console.error('Error fetching patients:', error);
        res.status(500).send('Failed to fetch patients');
    }
});

app.get('/admin/assign-specialists', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login');
    }

    try {
        // Find patients without an assigned specialist
        const unassignedPatients = await User.find({ 
            user_Role: 'Patient', 
            assignedSpecialistId: null 
        });

        // Find all specialists
        const specialists = await User.find({ user_Role: 'Specialist' });

        res.render('admin-assign-specialists', {
            unassignedPatients,
            specialists,
            role: req.session.role
        });
    } catch (error) {
        console.error('Error fetching unassigned patients:', error);
        req.flash('error', 'Failed to fetch unassigned patients');
        res.redirect('/admin/dashboard');
    }
});


// Reply to a message
app.post('/patient/reply-message/:messageId', async (req, res) => {
    const { messageContent } = req.body;
    const originalMessageId = req.params.messageId;

    const originalMessage = await Message.findById(originalMessageId);
    if (!originalMessage) {
        return res.status(404).send('Message not found');
    }

    const replyMessage = new Message({
        sender_id: req.session.userId, // Patient ID
        receiver_id: originalMessage.sender_id, // Send the reply to the Specialist
        message_content: messageContent,
        reply_to: originalMessageId // Link back to the original message
    });

    try {
        await replyMessage.save();

        // Create a notification for the specialist
        const notification = new Notification({
            notification_id: Date.now(),
            user_id: originalMessage.sender_id, // Specialist ID
            specialist_id: req.session.userId,
            notification_message: `You have received a new reply from your Patient.`,
            notification_type: 'New Reply'
        });

        await notification.save();
        req.flash('success', 'Reply sent successfully!'); // Set success message
        res.redirect('back'); // Redirect or render success response
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to send reply. Please try again.'); // Set error message
        res.status(500).send('Failed to reply to message');
    }
});

// Specialist view messages
app.get('/specialist/messages', async (req, res) => {
    // Check if the user is authenticated and has the correct role
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login'); // Redirect if not logged in or not a specialist
    }

    try {
        // Fetch all messages where the receiver is the specialist
        const messages = await Message.find({ receiver_id: req.session.userId })
            .populate('sender_id', 'user_FirstName user_LastName')
            .sort({ message_date: -1 });

        // Fetch the patients for the specialist
        const patients = await User.find({ assignedSpecialistId: req.session.userId }); // Adjust based on your assignment logic

        // Render the EJS template with messages and patients
        res.render('specialist-messages', { messages, patients: patients, role: req.session.role, loggedInSpecialistId: req.session.userId });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to fetch messages');
    }
});
// Patient view messages
app.get('/patient/messages', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Patient') {
        return res.redirect('/login'); // Redirect if not logged in or not a patient
    }

    try {
        const messages = await Message.find({ receiver_id: req.session.userId })
            .populate('sender_id', 'user_FirstName user_LastName')
            .sort({ message_date: -1 });

        // Get the loggedInPatientId (this must come from your user session)
        const loggedInPatientId = req.session.userId; // Or whatever logic you have

        res.render('patient-messages', { messages, role: req.session.role, loggedInPatientId });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to fetch messages');
    }
});

// Define your notification schema
const notificationSchema = new mongoose.Schema({
    notification_id: { type: Number, required: true, unique: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Users' },
    specialist_id: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Users' },
    notification_message: { type: String, required: true },
    notification_type: { type: String, required: true },
    notification_status: { type: String, default: 'Sent' }
}, { timestamps: true });

const Notification = mongoose.model('Notification', notificationSchema);




// Route to fetch notifications for a specialist
// Route to fetch notifications for a specialist
app.get('/specialist/notifications/:specialistId', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login');
    }

    const specialistId = req.params.specialistId;

    try {
        const notifications = await Notification.find({ specialist_id: specialistId })
            .populate('user_id', 'user_FirstName user_LastName')
            .populate('specialist_id', 'user_FirstName user_LastName');

        res.render('specialist-notifications', {
            notifications,
            successMessage: req.flash('success'), // Pass success message
            errorMessage: req.flash('error'), // Pass error message
            role: req.session.role,
            loggedInSpecialistId: specialistId
        });
    } catch (error) {
        console.error('Error fetching notifications:', error);
        req.flash('error', 'Failed to fetch notifications'); // Set error message
        return res.redirect('/admin/dashboard'); // Redirect to a safe page
    }
});
// Route to fetch notifications for a patient
app.get('/patient/notifications/:patientId', async (req, res) => {
    const patientId = req.params.patientId;
 
    if (!req.session.userId || req.session.role !== 'Patient') {
        return res.redirect('/login'); // Redirect if not a patient
    }

    try {
        const notifications = await Notification.find({ user_id: patientId }); // Fetch notifications for the patient
        
        res.render('patient-notifications', {
            notifications,
            successMessage: req.flash('success'), // Pass success messages to template
            errorMessage: req.flash('error'),     // Pass error messages to template
            role: req.session.role,
            loggedInPatientId: patientId
        });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to retrieve notifications'); // Pass error message
        return res.redirect('/patient/notifications/' + patientId); // Redirect back on error
    }
});

// Route to delete the notification
app.post('/notifications/delete/:notificationId', async (req, res) => {
    const notificationId = req.params.notificationId;

    // Check if the user is authenticated
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect if not logged in
    }

    try {
        await Notification.findByIdAndDelete(notificationId); // Delete the notification from the database
        console.log("Success message set:", req.flash('success'));
        
        // Redirect to the appropriate notifications page based on user role
        if (req.session.role === 'Patient') {
            req.flash('success', 'Notification deleted successfully!'); // Set success flash message

            return res.redirect(`/patient/notifications/${req.session.userId}`); // Redirect to patient's notifications
        } else if (req.session.role === 'Specialist') {
            req.flash('success', 'Notification deleted successfully!'); // Set success flash message

            return res.redirect(`/specialist/notifications/${req.session.userId}`); // Redirect to specialist's notifications
        } else {
            return res.redirect('/'); // Fallback in case of an unexpected role
        }  
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to delete notification'); // Set error flash message
        return res.redirect(req.get("Referrer") || '/'); // Use the referrer URL or fallback to home // Redirect back on error
    }
});
// Route to delete the notification
app.post('/specialist/notifications/delete/:notificationId', async (req, res) => {
    const notificationId = req.params.notificationId;

    // Check if the user is authenticated
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect if not logged in
    }

    try {
        await Notification.findByIdAndDelete(notificationId); // Delete the notification from the database
        
        // Set success flash message
        req.flash('success', 'Notification deleted successfully!');
        
        // Fetch notifications for the specialist after deletion
        const notifications = await Notification.find({ specialist_id: req.session.userId })
            .populate('user_id', 'user_FirstName user_LastName') // Populate user data
            .populate('specialist_id', 'user_FirstName user_LastName'); // Populate specialist info
        
        // Render the notifications page with the messages
        res.render('specialist-notifications', {
            notifications,
            successMessage: req.flash('success'), // Pass success message
            errorMessage: req.flash('error'),     // Pass any error message
            role: req.session.role,
            loggedInSpecialistId: req.session.userId,  // Pass logged-in specialist ID
        });
    } catch (error) {
        console.error('Failed to delete notification:', error);
        req.flash('error', 'Failed to delete notification'); // Set error flash message
        return res.redirect('/'); // Fallback to home in case of error
    }
});
// Route to view a single notification
app.get('/notifications/:notificationId', async (req, res) => {
    const notificationId = req.params.notificationId;
    console.log(`Fetching notification with ID: ${notificationId}`);

    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        const notification = await Notification.findById(notificationId)
            .populate('user_id', 'user_FirstName user_LastName')
            .populate('specialist_id', 'user_FirstName user_LastName');

        if (!notification) {
            console.log('Notification not found');
            return res.status(404).send('Notification not found');
        }

        const userRole = req.session.role;
        let userId = null;

        if (userRole === 'Patient') {
            userId = req.session.userId;
        } else if (userRole === 'Specialist') {
            userId = req.session.userId;
        }

        res.render('notification-detail', {
            notification,
            role: userRole,
            userId,
            loggedInPatientId: userRole === 'Patient' ? userId : null,
            loggedInSpecialistId: userRole === 'Specialist' ? userId : null
        });
    } catch (error) {
        console.error('Error fetching notification details:', error);
        res.status(500).send('Failed to fetch notification details');
    }
});

// Route to view all users (admin users page)
// Route to view all users (admin users page)
app.get('/admin/users', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if not logged in or not an admin
    }

    try {
        const users = await User.find(); // Retrieve all users
        const successMessage = req.flash('success'); // Retrieve the success message
        const errorMessage = req.flash('error');     // Retrieve the error message

        // Render the admin users page with the messages
        res.render('admin-users', {
            users,
            role: req.session.role,
            successMessage: successMessage.length ? successMessage[0] : null, // Pass success message
            errorMessage: errorMessage.length ? errorMessage[0] : null // Pass error message
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send('Failed to fetch users');
    }
});


// Route to view a single user's details
app.get('/admin/users/:id', async (req, res) => {
    const userId = req.params.id;

    // Check if the user is authenticated and is an Admin
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if not logged in or not an admin
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Pass user and role to the template
        res.render('admin-user-detail', { user, role: req.session.role });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to fetch user details');
    }
});

// Route to display edit user form
app.get('/admin/users/edit/:id', async (req, res) => {
    const userId = req.params.id;

    // Check if the user is authenticated and is an Admin
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if not logged in or not an admin
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Retrieve flash messages for display
        const successMessage = req.flash('success'); 
        const errorMessage = req.flash('error'); 
        
        console.log('On render:', successMessage, errorMessage);
        
        // Render the edit user page with user details and flash messages
        res.render('admin-edit-user', {
            user,
            role: req.session.role,
            successMessage,
            errorMessage
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to fetch user details for editing');
    }
});
// Handle the update user form submission
app.post('/admin/users/edit/:id', async (req, res) => {
    const userId = req.params.id;
    const { firstName, lastName, email, address, phoneNo, dob, role, specialistType } = req.body;

    // Check if the user is authenticated and is an Admin
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if not logged in or not an admin
    }

    try {
        await User.findByIdAndUpdate(userId, {
            user_FirstName: firstName,
            user_LastName: lastName,
            user_Email: email,
            user_Address: address,
            user_PhoneNo: phoneNo,
            user_DOB: dob,
            user_Role: role,
            user_SpecialistType: specialistType
        });

        // Set flash message correctly
        req.flash('success', 'User updated successfully!');

        // Redirect back to the same edit page with a success message
        return res.redirect(`/admin/users/edit/${userId}`); 
    } catch (error) {
        req.flash('error', 'Failed to update user'); // Set error message
        return res.redirect(`/admin/users/edit/${userId}`); // Redirect back to edit page
    }
});
// Route to delete a user
app.post('/admin/users/delete/:id', async (req, res) => {
    const userId = req.params.id;

    // Check if the user is authenticated and is an Admin
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login'); // Redirect if not logged in or not an admin
    }

    try {
        await User.findByIdAndDelete(userId);
        req.flash('success', 'User deleted successfully!'); // Set success message

        console.log('Success message set:', req.flash('success'));
        res.redirect('/admin/users'); // Redirect to user list
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to delete user'); // Set error message
        res.redirect('/admin/users'); // Redirect back to user list with error message
    }
});

// Manage patients for a specialist
app.get('/manage-patients', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login'); // Redirect if not logged in or not a specialist
    }

    try {
        const specialistId = req.session.userId; // Get logged-in specialist ID
        const patients = await User.find({ assignedSpecialistId: specialistId }).populate('assignedSpecialistId');
        console.log("Patients:", patients);// Fetch patients assigned to the specialist
        const labReports = await LabReport.find({ user_id: { $in: patients.map(p => p._id) } }); // Fetch lab reports for patients

        // Render the manage-patients view with the list of patients and any additional data
        res.render('manage-patients', {
            patients,
            labReports,
            role: req.session.role,
            loggedInSpecialistId: specialistId // Pass the specialist ID to the view
        });
    } catch (err) {
        console.error('Error fetching patients:', err);
        res.status(500).send('Failed to fetch patients');
    }
});
// Specialist can view their bookings
app.get('/specialist/bookings', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login');
    }

    try {
        const specialistId = req.session.userId;
        const bookings = await Appointment.find({ specialistId }) // Fetch books made with this specialist
            .populate('patientId', 'user_FirstName user_LastName'); // Populate patient names

        res.render('specialist-bookings', {
            bookings,
            role: req.session.role,
            loggedInSpecialistId: specialistId
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching bookings');
    }
});

// Availability Model
const AvailabilitySchema = new mongoose.Schema({
    specialistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    date: { type: Date, required: true },
    availableFrom: { type: Date, required: true },
    availableTo: { type: Date, required: true }
});

const Availability = mongoose.model('Availability', AvailabilitySchema);



// Get Specialist Availability
app.get('/specialist/availability', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login');
    }

    const selectedDate = req.query.date || new Date().toISOString().split('T')[0]; // Default to today if no date is selected

    try {
        const specialistId = req.session.userId;
        const availabilityList = await Availability.find({
            specialistId,
            date: {
                $gte: new Date(selectedDate).setHours(0, 0, 0, 0),
                $lt: new Date(selectedDate).setHours(23, 59, 59, 999)
            }
        }).sort({ availableFrom: 1 });

        res.render('specialist-availability', {
            availabilityList,
            selectedDate, // Pass the selected date to the template
            role: req.session.role,
            loggedInSpecialistId: specialistId
        });
    } catch (error) {
        console.error('Error retrieving availability:', error);
        res.status(500).send('Failed to retrieve availability');
    }
});

// Set Availability Route
app.post('/specialist/availability', async (req, res) => {
    const { date, timeSlot } = req.body;
    console.log(`Received date: ${date}, timeSlot: ${timeSlot}`);

    // Validate date input
    if (!date || !timeSlot) {
        req.flash('error', 'Date and time slot are required.');
        return res.redirect(`/specialist/availability?date=${date}`);
    }

    // Convert time to 24-hour format if necessary
    const [start, end] = timeSlot.split(" - ").map(time => {
        return moment(time, ["h:mm A"]).format("HH:mm");
    });

    // Parse the date and time using moment
    const availableFrom = moment(`${date}T${start}`, "YYYY-MM-DDTHH:mm").toDate();
    const availableTo = moment(`${date}T${end}`, "YYYY-MM-DDTHH:mm").toDate();

    console.log(`Parsed availableFrom: ${availableFrom}, availableTo: ${availableTo}`);

    // Validate parsed dates
    if (isNaN(availableFrom.getTime()) || isNaN(availableTo.getTime()) || availableFrom >= availableTo) {
        req.flash('error', 'Invalid time selection. Please try again.');
        return res.redirect(`/specialist/availability?date=${date}`);
    }

    try {
        const specialistId = req.session.userId;
        console.log(`Specialist ID: ${specialistId}`);

        // Check if the time slot is already booked
        const existingAvailability = await Availability.findOne({
            specialistId,
            date: new Date(date),
            $or: [
                { availableFrom: { $lt: availableTo, $gte: availableFrom } },
                { availableTo: { $gt: availableFrom, $lte: availableTo } },
                { availableFrom: { $lte: availableFrom }, availableTo: { $gte: availableTo } }
            ]
        });

        if (existingAvailability) {
            req.flash('error', 'This time slot is already booked. Please select another one.');
            return res.redirect(`/specialist/availability?date=${date}`);
        }

        // Save the new availability
        const availability = new Availability({ specialistId, date: new Date(date), availableFrom, availableTo });
        await availability.save();
        req.flash('success', 'Availability set successfully!');
        return res.redirect(`/specialist/availability?date=${date}`);
    } catch (err) {
        console.error('Error saving availability:', err);
        req.flash('error', 'Failed to save availability.');
        return res.redirect(`/specialist/availability?date=${date}`);
    }
});

// Route to get available slots for a specialist on a particular date
app.get('/appointments/available-slots/:specialistId/:date', async (req, res) => {
    const { specialistId, date } = req.params;

    try {
        const availabilities = await Availability.find({
            specialistId: specialistId,
            date: new Date(date)
        });

        const bookedAppointments = await Appointment.find({
            specialistId: specialistId,
            Appointments_date: {
                $gte: new Date(`${date}T00:00:00`),
                $lt: new Date(`${date}T23:59:59`)
            }
        });

        const bookedSlots = bookedAppointments.map(appointment => {
            return appointment.Appointments_date.toTimeString().slice(0, 5);
        });

        const availableSlots = [];
        availabilities.forEach(avail => {
            const slots = generateTimeSlots(avail.availableFrom, avail.availableTo, 45);
            slots.forEach(slot => {
                if (!bookedSlots.includes(slot.start)) {
                    availableSlots.push(slot); // Only add if not booked
                }
            });
        });

        res.json(availableSlots);
    } catch (error) {
        console.error('Error fetching available slots:', error);
        return res.status(500).send('Failed to fetch available slots');
    }
});

// Function to generate time slots
function generateTimeSlots(start, end, interval) {
    const slots = [];
    const current = new Date(start);

    while (current < end) {
        const slotStart = new Date(current);
        current.setMinutes(current.getMinutes() + interval);
        const slotEnd = new Date(current);

        slots.push({
            start: slotStart.toTimeString().slice(0, 5), // Ensure HH:mm format
            end: slotEnd.toTimeString().slice(0, 5) // Ensure HH:mm format
        });
    }

    return slots;
}

// Route to view managing details of a specific patient
app.get('/specialist/patient/:patientId/details', async (req, res) => {
    const patientId = req.params.patientId;

    // Check if the user is authenticated and is a Specialist
    if (!req.session.userId || req.session.role !== 'Specialist') {
        return res.redirect('/login'); // Redirect if not logged in or not a specialist
    }

    try {
        // Fetch patient details
        const patient = await User.findById(patientId);
        if (!patient) {
            return res.status(404).send('Patient not found'); // Patient not found
        }

        // Fetch lab reports and appointments for the patient if needed
        const labReports = await LabReport.find({ user_id: patientId });
        const appointments = await Appointment.find({ patientId }).populate('specialistId');

        // Get the logged-in specialist ID from the session
        const loggedInSpecialistId = req.session.userId;

        // Render the patient details page, including the loggedInSpecialistId and moment
        res.render('patient-details', {
            patient,
            labReports,
            appointments,
            role: req.session.role,
            loggedInSpecialistId, // Pass loggedInSpecialistId to the view
            moment // Pass moment to the view
        });
    } catch (error) {
        console.error('Failed to fetch patient details:', error);
        res.status(500).send('Failed to fetch patient details');
    }
});
// Route to view a patient's own details
app.get('/patient/details', async (req, res) => {
    const userId = req.session.userId;

    // Check if the user is authenticated and is a Patient
    if (!userId || req.session.role !== 'Patient') {
        return res.redirect('/login'); // Redirect if not logged in or not a patient
    }

    try {
        // Fetch patient details
        const patient = await User.findById(userId);
        if (!patient) {
            return res.status(404).send('Patient not found'); // Patient not found
        }

        // Fetch lab reports, appointments, and emergency contact for the patient
        const labReports = await LabReport.find({ user_id: userId });
        const appointments = await Appointment.find({ patientId: userId }).populate('specialistId');
        const emergencyContact = patient.emergencyContact; // assuming patient document has an emergencyContact field

        // Render the patient details page
        res.render('patient-details', {
            patient,
            labReports,
            appointments,
            emergencyContact,
            role: req.session.role,
            moment // Pass moment to the view
        });
    } catch (error) {
        console.error('Failed to fetch patient details:', error);
        res.status(500).send('Failed to fetch patient details');
    }
});

// Route to delete a message
app.post('/messages/delete/:messageId', async (req, res) => {
    const messageId = req.params.messageId;

    // Check if the user is authenticated
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect if not logged in
    }

    try {
        await Message.findByIdAndDelete(messageId); // Delete the message
        req.flash('success', 'Message deleted successfully!'); // Set success flash message
    } catch (error) {
        console.error('Error deleting message:', error);
        req.flash('error', 'Failed to delete message'); // Set error flash message
    }

    // Redirect back to the messages page based on user role
    if (req.session.role === 'Patient') {
        return res.redirect('/patient/messages');
    } else if (req.session.role === 'Specialist') {
        return res.redirect('/specialist/messages');
    } else {
        return res.redirect('/'); // Fallback in case of an unexpected role
    }  
});
// Logout Route
app.post('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy(err => {
        if (err) {
            console.error(err);
            return res.status(500).send('Could not log out. Please try again.');
        }

        // Redirect to the login page after successful logout
        res.redirect('/');
    });
});



const contactMessageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);
// Route to display the contact form
// Route to display the contact form
app.get('/contact-us', (req, res) => {
    const role = req.user ? req.user.role : null; // Check if user is logged in
    const loggedInSpecialistId = req.user ? req.user.id : null; // Check if user is logged in

    res.render('contact-us', {
        role,
        loggedInSpecialistId,
        successMessage: req.flash('success'),
        errorMessage: req.flash('error')
    });
});

// Route to handle form submission
app.post('/contact-us', async (req, res) => {
    const { name, email, message } = req.body;

    try {
        const newMessage = new ContactMessage({ name, email, message });
        await newMessage.save();

        req.flash('success', 'Your message has been sent successfully!');
        res.redirect('/contact-us');
    } catch (error) {
        console.error('Error saving contact message:', error);
        req.flash('error', 'Failed to send your message. Please try again.');
        res.redirect('/contact-us');
    }
});

// Admin route to view messages
app.get('/admin/admin-messages', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'Admin') {
        return res.redirect('/login');
    }

    try {
        const messages = await ContactMessage.find().sort({ date: -1 });
        res.render('admin-messages', { messages, role: req.session.role });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).send('Failed to fetch messages');
    }
});



// Start Server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});