# Project 7 - WordPress Pentesting

Time spent: **7** hours spent in total

> Objective: Find, analyze, recreate, and document **three vulnerabilities** affecting an old version of WordPress

## Pentesting Report

### 1. Viewing Unauthenticated Posts (CVE-2019-17671)
  - [ ] Summary: 
    - Vulnerability types: Privilege Escalation (maybe). This allows hidden content to be revealed to any hacker. 
    - Tested in version: 4.2
    - Fixed in version: 5.2.4
  - [ ] GIF Walkthrough: This shows that the admin has created the pages and they are unable to be accessed by an anonymous user, until they do the URL manipulation.
![Alt Text](Explot2.gif)

  - [ ] Steps to recreate: 
   1) Go to homepage of WordPress site, in this case it is `http://wpdistillery.vm/`
   2) Add the following to the end of the URL of the homepage: `?static=1&order=asc` (Note that sometimes "asc" does not work, so you might want to try `?static=1&order=asc`). For example, I had `http://wpdistillery.vm/?static=1&order=asc`
  - [ ] Affected source code: `var_dump()`
  ```
  		// Check post status to determine if post should be displayed.
		if ( ! empty( $this->posts ) && ( $this->is_single || $this->is_page ) ) {
			$status = get_post_status( $this->posts[0] );
			if ( 'attachment' === $this->posts[0]->post_type && 0 === (int) $this->posts[0]->post_parent ) {
				$this->is_page       = false;
				$this->is_single     = true;
				$this->is_attachment = true;
			}
			$post_status_obj = get_post_status_object( $status );

            //PoC: Let's see what we have
			//var_dump($q_status);
			//var_dump($post_status_obj);
			// If the post_status was specifically requested, let it pass through.
			if ( ! $post_status_obj->public && ! in_array( $status, $q_status ) ) {
				//var_dump("PoC: Incorrect status! :-/");
				if ( ! is_user_logged_in() ) {
					// User must be logged in to view unpublished posts.
					$this->posts = array();
					//var_dump("PoC: No posts :-(");
				} else {
					if ( $post_status_obj->protected ) {
						// User must have edit permissions on the draft to preview.
						if ( ! current_user_can( $edit_cap, $this->posts[0]->ID ) ) {
							$this->posts = array();
						} else {
							$this->is_preview = true;
							if ( 'future' != $status ) {
								$this->posts[0]->post_date = current_time( 'mysql' );
							}
						}
					} elseif ( $post_status_obj->private ) {
						if ( ! current_user_can( $read_cap, $this->posts[0]->ID ) ) {
							$this->posts = array();
						}
					} else {
						$this->posts = array();
					}
				}
			}
  ```
  - [ ] Sources/Citations: 
- **Source 1**: https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
### 2. Stored XSS in Comment (CVE-2015-3440)
  - [ ] Summary: 
    - Vulnerability types: XSS (Cross-Site Scripting). This can cause anyone who visits the page to run a malicious Javascript upon visitng the website. 
    - Tested in version: 4.2
    - Fixed in version: 4.2.1
  - [ ] GIF Walkthrough: **Please ignore the homepage title, I forgot to change it for the current exploit, but it does not affect anything**
  ![Alt Text](Untitled.gif) 
  - [ ] Steps to recreate: 
  1. As an anonymous user, post a comment in the following format: `<a title='x onmouseover=alert(unescape(/hello%20world/.source)) style=position:absolute;left:0;top:0;width:5000px;height:5000px  AAAAAAAAAAAAAAA..AAA'></a>`. But you have to write 640k A's to make the message long enough. Refer to the file **StoredXSSComment** in repository to get the full comment to copy-and-paste
  2. If the admin requires comment approval, then the admin might approve the comment
  3. Then, when the admin goes to the page on which the comment is posted, the Javascript will run and create a "hello word" alert.
  - [ ] Affected source code: Unsure
  - [ ] Sources/Citations
    - **Source 1:** https://www.exploit-db.com/exploits/36844
    - **Source 2:** https://klikki.fi/adv/wordpress2.html
    - **Source 3:** https://www.youtube.com/watch?v=OCqQZJZ1Ie4
### 3. Explore and Access the Full Directory of a WordPress site (CVE-2019-8943)
  - [ ] Summary: 
    - Vulnerability types: URL manipulation. This allows a user to access all of the site's CSS and Javascript files, possibly revealing sensitive information. 
    - Tested in version: 4.2
    - Fixed in version: 4.3 (I think; admins have an option to disable directory browsing in Security settings)
  - [ ] GIF Walkthrough: **This starts off by showing that I am not logged in as admin. Yet, I can still browse the directory of Javascript and CSS information.**
  ![Alt Text](Exploit-3.gif)
  - [ ] Steps to recreate: 
  1. The admin should not have added any additional security measures
  2. Any user should go to the homepage of the WordPress site, in this case it is `http://wpdistillery.vm/`
  3. Then, add the following to the end of the homepage link: `wp-admin/js/` or `wp-admin/css/`. For example, I used: `http://wpdistillery.vm/wp-admin/js/`
  4. Now, the user can browse all of the CSS and Javascript files and see their content. Now, they can access potentially sensitive content. 
  - [ ] Affected source code: \wp-content
  - [ ] Sources/Citations:
    - **Link 1:** https://security.stackexchange.com/questions/160651/what-are-sensitive-wordpress-site-directories
    - **Link 2:** https://www.wpbeginner.com/wp-tutorials/disable-directory-browsing-wordpress/
    - **Link 3:** https://www.acunetix.com/vulnerabilities/web/wordpress-directory-traversal-3-7-5-0-3/
    - **Link 4:"** https://cwe.mitre.org/data/definitions/548.html


## Assets

![Alt Text](StoredXSSCode)
## Resources

- [WordPress Source Browser](https://core.trac.wordpress.org/browser/)
- [WordPress Developer Reference](https://developer.wordpress.org/reference/)

GIFs created with [LiceCap](http://www.cockos.com/licecap/).

## Notes

Describe any challenges encountered while doing the work

## License

    Copyright [yyyy] [name of copyright owner]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
