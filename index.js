const express = require('express'); 
const helmet = require('helmet'); 
const cors = require('cors'); 
const bcrypt = require('bcryptjs'); 

server.use(helmet()); 
server.use(express.json());
server.use(cors('headers')); 


const port = process.env.PORT || 5000; 

server.listen(port, () => {
    console.log(`\n** running on port ${port} **\n`); 
})