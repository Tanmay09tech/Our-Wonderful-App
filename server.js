            //Accessing Enviroment Variables
            require('dotenv').config();
            //JSON Web Token
            const jwt = require("jsonwebtoken");
          // Importing marked
            const marked = require('marked');
            //Sanitize HTML
            const sanitizeHTML = require('sanitize-html');
            //Hashing the password
            const bcrypt = require("bcrypt");
            //Importing cookie parser
            const cookieParser = require("cookie-parser");
            //Importing express
            const express = require("express");
            //Create a database
            const db = require("better-sqlite3")('database.db');
            //Improve the performance of the database
            db.pragma('journal_mode = WAL');

            //Database set up here
            const createTables= db.transaction(
              //db.transaction lets u run multiple queries/statements
              () => {
              //structure of our table
              
              // Enable foreign keys
              db.prepare('PRAGMA foreign_keys = ON;').run();

              //Users table
              db.prepare(
                `CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              password TEXT NOT NULL
            )
            `).run()

            //Posts table
            db.prepare(
              `
              CREATE TABLE IF NOT EXISTS posts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              createdDate TEXT NOT NULL,
              title STRING NOT NULL,
              body TEXT NOT NULL,
              authorId INTEGER NOT NULL,
              
              FOREIGN KEY (authorId) REFERENCES users(id)
              )
              `
              //Foreign Key is referencing the authorId to the id in the users table
            ).run()
              });

            //database set up ends
            createTables();

            const app = express();

            app.set('view engine', 'ejs');
            app.use(express.urlencoded({ extended: true }));

            app.use(express.static('public'));

            //Calling cookie parser
            app.use(cookieParser());

            // Middleware
            app.use(function(req, res, next) {

            //make our marked function available 
              res.locals.filterUserHTML = function(content) {
                return sanitizeHTML(
                  //String that you are trying to sanitize 
                  marked.parse(content)
                  // Configuration object
                  ,{ allowedTags: ["p", "br","ul", "ol", "li", "b", "i", "em", "strong", "h1", "h2", "h3", "h4", "h5", "h6"],
                    allowedAttributes: {}
                  })
              }

              // errors array
              res.locals.errors = [];

            //try to decode incoming cookie 
            try{
              const decoded = jwt.verify(
                //super long token to check if this is legitimate
                req.cookies.OurSimpleApp,
              //secret value
              process.env.JWTSECRET
              )
              //If it is legit
              req.user = decoded
            }
            catch(err) {
              //If it is not
              req.user = false
            }
            //Access the cookie from any ejs template
            res.locals.user = req.user
              next();
            });

            // Routes

          // Homepage Route
            app.get('/', (req, res) => {
              if (req.user) {
                const postsStatement = db.prepare(
                  " SELECT * FROM posts WHERE authorId = ? ORDER BY createdDate DESC"
                  // * means select all
                )

                const posts = postsStatement.all(req.user.userid)
                // req.user.userid points to ? in the query
                return res.render("dashboard", { posts })
              }
              
              
              res.render('homepage');
            });
          
            // Login Route
            app.get('/login', (req, res) => {
              res.render('login');
            });
            app.get('/logout', (req, res) => {
              res.clearCookie('OurSimpleApp');
              res.redirect('/register');
            });
            app.get('/register', (req, res) => {
              res.render('register', { errors: [] }); // Render the registration page
          });
            
        // Login Submission Route
          app.post('/login', (req, res) => {
            let errors = [];
            if (typeof req.body.username !== 'string') req.body.username = '';
            if (typeof req.body.password !== 'string') req.body.password = '';
            if(req.body.username.trim()==='' || req.body.password.trim()===''){
              errors=['Invalid username or password'];
            }
            if(errors.length) {
              return res.render("login", {errors});
            }
            //looking up the user in the database
            const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE username = ?");
            //
            //checking if username exists
            const userInQuestion = userInQuestionStatement.get(req.body.username);
          
            if(!userInQuestion){
              errors=['Invalid username or password'];
              return res.render("login", {errors});
            }
            //
            //checking if password matches
            const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password);

            if(!matchOrNot){
              errors=['Invalid username or password'];
              return res.render("login", {errors});
            }
          //
            
            //give them a cookie
            const ourTakenValue = jwt.sign(
              //object
              { exp: Math.floor(
                //Current time
                Date.now() / 1000)
                // + 1 day
                + (60 * 60 * 24),
                skyColor: "blue",
                userid: userInQuestion.id,
                username: userInQuestion.username
              },
              //Secret value
              process.env.JWTSECRET)
              res.cookie(
              //cookie name
              "OurSimpleApp",
              //cookie value
              ourTakenValue,
            //configuration object 
            {
              httpOnly: true,
              secure: true,
              //CSRF protection
              sameSite:"strict",
              maxAge:1000 * 60 * 60 * 24
            }
            )

            // On successful registration, show the dashboard
            res.redirect('/');
            //redirect to homepage

          });

          //Create Post Route
          function mustBeLoggedIn(req, res, next) {
            if(req.user){ // req.user checks if the user is logged in
              return next()
            }
            else{
              res.redirect('/login')
              
            }
          }
            app.get("/create-post",mustBeLoggedIn, (req, res) => {
              res.render('create-post');
            })

            function sharedPostValidation(req){
              const errors = [];

              if (typeof req.body.title !== 'string') req.body.title = '';
              if (typeof req.body.body !== 'string') req.body.body = '';
              //trim-sanitize or strip out html
              req.body.title = sanitizeHTML(
                //String that you are trying to clean up
                req.body.title.trim(),
                // Configuration object
                {allowedTags: [], allowedAttributes: {}})

                req.body.body = sanitizeHTML(
                  //String that you are trying to clean up
                  req.body.body.trim(),
                  // Configuration object
                  {allowedTags: [], allowedAttributes: {}})
                if(!req.body.title){
                  errors.push('Title is required')
                } 
                if(!req.body.body){
                  errors.push('Content is required')
                }
              return errors
            }

            // Edit Post Route
            app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
              //try to look up the post in question
              const statement=db.prepare("SELECT * FROM posts WHERE id = ?")
              const postInQuestion=statement.get(req.params.id)
              if(!postInQuestion){
                return res.redirect("/")
              }
            //otherwise render the edit post template
              res.render("edit-post", {post : postInQuestion})
            })

            // Edit Post Submission Route
            app.post("/edit-post/:id",mustBeLoggedIn,(req, res) => {
              //try to look up the post in question
              const statement=db.prepare("SELECT * FROM posts WHERE id = ?")
              const postInQuestion=statement.get(req.params.id)
            
            
              
              const errors = sharedPostValidation(req)
            if (errors.length) {
              return res.render("edit-post", {errors})
            }
            
            const updateStatement=db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
            updateStatement.run(req.body.title, req.body.body, req.params.id)

            // Redirect to the updated post's page
        res.redirect(`/post/${req.params.id}`);
            })
            
            // Delete Post Route
            app.post("/delete-post/:id",mustBeLoggedIn,(req, res) => {
              const statement=db.prepare("SELECT * FROM posts WHERE id = ?")
              const postInQuestion=statement.get(req.params.id)
              if(!postInQuestion){
                return res.redirect("/")
              }
              const deleteStatement=db.prepare("DELETE FROM posts WHERE id = ?")
              deleteStatement.run(req.params.id)

              res.redirect("/")
            })

              // Single Post View Route
            app.get("/post/:id", (req, res) => {
              const statement = db.prepare(
                "SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorId = users.id WHERE posts.id = ?"
              )
              //to get something from the URL we use req.params
              const post = statement.get(req.params.id)

              if(!post){
                return res.redirect("/")
              }
              res.render("single-post", {post})

            })

            // Create Post Submission Route 
            app.post("/create-post",mustBeLoggedIn, (req, res) => {
            const errors = sharedPostValidation(req)
            if(errors.length){
              return res.render("create-post", {errors})
            }

            //save into database
            // Prepare a SQL statement to insert a new post into the 'posts' table
            const ourStatement=db.prepare(
              "INSERT INTO posts (title, body,authorId,createdDate) VALUES (?,?,?,?)"
            )

            
            // Run the insert statement with data from the request body and user information
            const result=ourStatement.run(req.body.title, req.body.body,req.user.userid,new Date().toISOString())
            // `req.body.title`, `req.body.body`, and `req.user.userid` are used to fill in title, body, and user ID fields
            // `new Date().toISOString()` provides the current date and time in ISO format for 'createdDate'

            // Prepare a SQL statement to retrieve the newly inserted post by its row ID
            const getPostStatement= db.prepare("SELECT * FROM posts WHERE ROWID= ?")

            // Fetch the new post data using the last inserted row ID from the result of the previous insert operation
            const realPost=getPostStatement.get(result.lastInsertRowid)

            // Redirect the user to the new post's page using the post's ID
            res.redirect(`/post/${realPost.id}`)
            //
            })

            // Register Submission Route
            app.post('/register', (req, res) => {
              const errors = [];
              
              if (typeof req.body.username !== 'string') req.body.username = '';
              if (typeof req.body.password !== 'string') req.body.password = '';

              req.body.username = req.body.username.trim();

              // Username validations
              if (!req.body.username) errors.push('Username is required');
              if (req.body.username && req.body.username.length < 3) errors.push('Username must be at least 3 characters');
              if (req.body.username && req.body.username.length > 10) errors.push('Username must not be more than 10 characters');
              if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push('Username can only contain letters and numbers');

              // Password validations
              if (!req.body.password) errors.push('Password is required');
              if (req.body.password && req.body.password.length < 6) errors.push('Password must be at least 6 characters');
              if (req.body.password && req.body.password.length > 20) errors.push('Password must not be more than 20 characters');

              if (errors.length) {
                return res.render('login', { errors });
              }
              // **Check if username already exists**
              const usernameStatement = db.prepare('SELECT * FROM users WHERE username = ?')
              const usernameCheck = usernameStatement.get(req.body.username);
            if (usernameCheck) {
              errors.push('Username is already taken');
              return res.render('login', { errors });
            }

              //save the user into a database

              //Hash the password
              const salt = bcrypt.genSaltSync(10)
              req.body.password = bcrypt.hashSync(req.body.password, salt)
              //

              const ourStatement = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
              const result = ourStatement.run(req.body.username, req.body.password)
              //LookUp the item in the database
              const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")

              //Retrieve the item from the database
              const ourUser = lookupStatement.get(result.lastInsertRowid)

              //log the user in by giving them a cookie

              const ourTakenValue = jwt.sign(
                //object
                { exp: Math.floor(
                  //Current time
                  Date.now() / 1000)
                  // + 1 day
                  + (60 * 60 * 24),
                  skyColor: "blue",
                  userid: ourUser.id,
                  username: ourUser.username
                },
                //Secret value
                process.env.JWTSECRET)
              

              

              res.cookie(
                //cookie name
                "OurSimpleApp",
                //cookie value
                ourTakenValue,
              //configuration object 
              {
                httpOnly: true,
                secure: true,
                //CSRF protection
                sameSite:"strict",
                maxAge:1000 * 60 * 60 * 24
              }
              )

            

              // On successful registration, show the dashboard
              res.redirect('/dashboard');

            });

            // Dashboard Route
            app.get('/dashboard', (req, res) => {
              if (req.user) {
                return res.render('dashboard'); // Render dashboard if logged in
              }
              res.redirect('/login'); // Redirect to login if not authenticated
            });
            
            //

          app.listen(3001, () => {
              console.log('Server running on port 3001');
            });
