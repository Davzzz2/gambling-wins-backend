# Gambling Wins Backend

This is the backend server for the Gambling Wins application. It's built with Node.js, Express, and MongoDB.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
PORT=5000
```

3. Create an `uploads` directory in the root folder:
```bash
mkdir uploads
```

## Running the Server

To start the server in development mode:
```bash
node server.js
```

## API Endpoints

### Authentication
- POST `/api/login` - User login
- POST `/api/register` - User registration (admin only)

### Wins
- GET `/api/wins` - Get all wins
- POST `/api/wins` - Create a new win
- PUT `/api/wins/:id` - Update a win
- DELETE `/api/wins/:id` - Delete a win

### Users
- GET `/api/users/:username` - Get user profile
- GET `/api/users` - Get all users (admin only)

## Environment Variables

- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT token generation
- `PORT`: Server port (default: 5000)

## Deployment

1. Set up MongoDB Atlas for the database
2. Deploy to a hosting service (e.g., Render.com)
3. Set environment variables in the hosting platform
4. Ensure the uploads directory is properly configured 