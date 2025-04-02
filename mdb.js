// Connect to MongoDB
const { MongoClient } = require("mongodb");
const uri = "mongodb://localhost:27017/";
const client = new MongoClient(uri);

// Function to insert data
async function run() {
    try {
        await client.connect();
        const database = client.db("CareConnectDB");

        // Insert Users
        const usersCollection = database.collection("Users");
        await usersCollection.insertMany([
            { user_id: 1, user_FirstName: "John", user_LastName: "Doe", user_Email: "john.doe@example.com", user_Address: "123 Main St, Cityville", user_Password: "password123", user_PhoneNo: "123-456-7890", user_DOB: new Date("1985-05-15"), user_Role: "Patient" },
            { user_id: 2, user_FirstName: "Jane", user_LastName: "Smith", user_Email: "jane.smith@example.com", user_Address: "456 Elm St, Townsville", user_Password: "password456", user_PhoneNo: "234-567-8901", user_DOB: new Date("1990-08-20"), user_Role: "Patient" },
            { user_id: 3, user_FirstName: "Dr. Emily", user_LastName: "Johnson", user_Email: "emily.johnson@example.com", user_Address: "789 Oak St, Villageburg", user_Password: "password789", user_PhoneNo: "345-678-9012", user_DOB: new Date("1980-12-30"), user_Role: "Specialist" },
            { user_id: 4, user_FirstName: "Admin User", user_LastName: "Admin", user_Email: "admin@example.com", user_Address: "101 Admin St, Admin City", user_Password: "adminpassword", user_PhoneNo: "456-789-0123", user_DOB: new Date("1975-01-01"), user_Role: "Admin" }
        ]);

        // Insert Specialists
        const specialistsCollection = database.collection("Specialists");
        await specialistsCollection.insertMany([
            { Specialist_id: 1, user_id: 3, User_Name: "Dr. Emily Johnson", Specialist_Type: "Pediatrics" },
            { Specialist_id: 2, user_id: 3, User_Name: "Dr. Emily Johnson", Specialist_Type: "Psychiatry" }
        ]);

        // Insert Patient Records
        const patientRecordsCollection = database.collection("PatientRecords");
        await patientRecordsCollection.insertMany([
            { PatientRecord_id: 1, Specialist_id: 1, user_id: 1, PatientRecord_medical_history: "No known allergies. Previous surgeries: Appendectomy.", PatientRecord_emergency_contact: "Jane Doe, 123-456-7890" },
            { PatientRecord_id: 2, Specialist_id: 2, user_id: 2, PatientRecord_medical_history: "Asthma diagnosed at age 10. No other significant history.", PatientRecord_emergency_contact: "John Smith, 234-567-8901" }
        ]);

        // Insert Appointments
        const appointmentsCollection = database.collection("Appointments");
        await appointmentsCollection.insertMany([
            { Appointments_id: 1, user_id: 1, Specialist_id: 1, User_Name: "John Doe", Appointments_Availability: "Available", Appointments_date: new Date("2023-10-15T10:00:00Z"), Appointments_confirmation: "Confirmed", Appointment_type: "In-Person", Appointment_status: "Scheduled" },
            { Appointments_id: 2, user_id: 2, Specialist_id: 2, User_Name: "Jane Smith", Appointments_Availability: "Available", Appointments_date: new Date("2023-10-16T14:00:00Z"), Appointments_confirmation: "Pending", Appointment_type: "Video Consultation", Appointment_status: "Scheduled" }
        ]);

        // Insert Video Consultations
        const videoConsultationsCollection = database.collection("VideoConsultations");
        await videoConsultationsCollection.insertOne({
            VideoConsultations_id: 1,
            appointment_id: 2,
            Specialist_id: 2,
            user_id: 2,
            VideoConsultations_Link: "https://videochat.example.com/meeting123",
            VideoConsultations_status: "Scheduled",
            VideoConsultations_Notes: "Initial consultation for mental health assessment."
        });

        // Insert Lab Reports
        const labReportsCollection = database.collection("LabReports");
        await labReportsCollection.insertMany([
            { LabReports_id: 1, user_id: 1, Specialist_id: 1, LabReports_File: "lab_report_1.pdf", LabReports_Date: new Date("2023-10-10"), LabReports_Notes: "Routine check-up results. All normal." },
            { LabReports_id: 2, user_id: 2, Specialist_id: 2, LabReports_File: "lab_report_2.pdf", LabReports_Date: new Date("2023-10-11"), LabReports_Notes: "Asthma test results. Follow-up recommended." }
        ]);

        // Insert Notifications
        const notificationsCollection = database.collection("Notifications");
        await notificationsCollection.insertMany([
            { notification_id: 1, user_id: 1, Specialist_id: 1, notification_message: "Your appointment is confirmed for October 15, 2023.", notification_type: "Appointment Reminder", notification_status: "Sent" },
            { notification_id: 2, user_id: 2, Specialist_id: 2, notification_message: "Your lab report is ready for review.", notification_type: "Lab Report Ready", notification_status: "Pending" }
        ]);

        // Insert Out of Province Specialists
        const outOfProvinceCollection = database.collection("OutOfProvinceSpecialists");
        await outOfProvinceCollection.insertMany([
            { specialist_id: 1, full_name: "Dr. Sarah Connor", specialty: "Cardiology", province: "Ontario", availability_status: "Available" },
            { specialist_id: 2, full_name: "Dr. Bruce Wayne", specialty: "Orthopedics", province: "Alberta", availability_status: "Unavailable" }
        ]);

        // Insert Secure Messages
        const secureMessagesCollection = database.collection("SecureMessages");
        await secureMessagesCollection.insertOne({
            SecureMessages_id: 1,
            SecureMessages_sender_id: 1,
            SecureMessages_receiver_id: 2,
            SecureMessages_content: "Hi Jane, I wanted to discuss your recent lab results.",
            timestamp: new Date(),
            status: "Sent"
        });

        console.log("Data inserted successfully.");
    } catch (e) {
        console.error("Error inserting data: ", e);
    } finally {
        await client.close();
    }
}

run().catch(console.error);