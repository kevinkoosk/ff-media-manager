Flat File Media Manager
-----------------------
A simple flat file system used to upload media. (Uses PHP and Sqlite)

- Used to upload images, videos, audio, PDF, etc.
- Previously part of SPBlog blogging app (also by me - Kevin Koo Seng Kiat)
- However, I am separating it and developing it as a separate app.


- Ideally, we can put this on a subdomain like https://cdn.domain.ext
- This script can be used to manage a blog's CDN
- I do have a simple blog system that works with this. 

Features
========
1. Upload media - images, videos, audio, PDF, etc.
2. Filter media
3. Search media
4. Display media (click "view")
5. Rename media
6. Delete media
7. Images will have a thumbnail displayed.

User management
================
1. Add user
2. Change user password
3. Delete user (except admin)

Storage (Important!)
========
1. Uses SQLite for user management and to save settings.
2. The files should be uploaded to the ROOT folder of your domain or subdomain. 
3. The SQLite file will be created one level above (../) which is ideally not reachable from the browser.

Uploaded files
==============
1. The uploaded files are stored in a folder of their own and are automatically renamed randomly. 
2. The original names of the files are noted. (Stored in the Sqlite database.)
3. You can rename the files.

Disclaimer
==========
1. This app was created using vibe coding.
2. I am not a professional coder.

Copyright
=========
All copyright is claimed by Kevin Koo Seng Kiat.
