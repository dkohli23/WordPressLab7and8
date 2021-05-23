# Project 7 - WordPress Pentesting

Time spent: **7** hours spent in total

> Objective: Find, analyze, recreate, and document **three vulnerabilities** affecting an old version of WordPress

## Pentesting Report

### 1. Viewing Unauthenticated Posts (CVE-2019-17671)
  - [ ] Summary: 
    - Vulnerability types: URL Manipulation
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
### 2. Stored XSS in Comment (CVE: 2015-3440)
  - [ ] Summary: 
    - Vulnerability types: XSS (Cross-Site Scripting)
    - Tested in version: 4.2
    - Fixed in version: 4.2.1
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
### 3. (Required) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
### 4. (Optional) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
### 5. (Optional) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php) 

## Assets

List any additional assets, such as scripts or files

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
