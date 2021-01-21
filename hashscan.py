#!/usr/bin/env python3
#
# Application Security Assignment - Xeb3rnium
#
# pip install time requests filehash virustotal-api, progress
#
import os, time, requests, filehash, virus_total_apis, progress.bar

VT_ID = "b6dbf4ccabdd2965f6b4a22d22614162d619e1b9a810ea9ffd0b6ba40d291ffb" # API Key
HEADER = {"User-Agent": "AppSec B00105244"} # May not need this anymore because of virustotal-api



class colors: # May not work on Powershell, better to use Bash
	red = '\033[91m'
	green = '\033[92m'	
	cyan = '\033[96m'
	yellow = '\033[93m'
	default = '\033[0m'
	bold = '\033[1m'


curl = lambda url: requests.get(url, headers=HEADER, allow_redirects=True) # Public anonymous function for any HTTP requests



def main():
	print(f"\n-----{colors.cyan}Application Security CA3 File Scanner{colors.default}-----\n")
	cwd, wildcard = Menu() # Assign current directory and mask

	# Scan filesystem
	with progress.bar.ChargingBar("Scanning Directory:", max=1) as bar:
		hashsums = []
		result = Scanfilesystem(cwd, 'sha256', wildcard) # More efficient when called once
		try:
			for i in range(len(result)):
#				if Queryhashedb(hashsums[i]['hash']): # TODO: If NSLR result not found, add hash to json{} for VT otherwise skip
#					json = {"file": result[i][0], "hash": result[i][1]}
#					hashsums.append(json)
				json = {"file": result[i][0], "hash": result[i][1]} # Format everything into JSON for easier parsing
				hashsums.append(json) # Above could probably move into this
				bar.next()
		except FileError:
			print("Error in generating hashes")
	bar.finish

#	hashsums.append({"file": "EICAR TEST", "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}) # Add EICAR to list for testing
#	hashsums.append({"file": "WannaCry", "hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"}) # WannaCry sample

	# Query VirusTotal
	with progress.bar.ChargingBar("Querying VirusTotal:", max=len(hashsums)) as bar:
		responses = []
		try:
			for i in range(len(hashsums)):
				if len(hashsums) > 4: # Add timeout if file list is over speed limit, can get really slow
					responses.append(Queryvt(hashsums[i]['hash'])) # Feed VT reports into the list
					time.sleep(15) # Limit speed to 4 per minute
				else:
					responses.append(Queryvt(hashsums[i]['hash']))
				bar.next()
		except ConnectionError:
			print("Web Request Error")
	bar.finish


	# Generate Report
	Report(list(filter(None, responses)), hashsums) # Filter out None entries


	print(f"\n\n---------------{colors.cyan}Finished{colors.default}----------------\n")




#Main menu that takes in user parameters
def Menu():
	location = input("Enter directory path [.]: ")
	if location == "":
		cwd = "." # Default to current directory
	elif os.path.exists(location) != True: # Check if path is valid
		print("Not a valid path, try again\n")
		Menu() # Might need refactoring if this is more than once
	else:
		cwd = location

	regex = input("Enter file wildcard [*]: ") # May need error handling
	if regex == "":
		wildcard = "*" # Default to everything in directory
	else:
		wildcard = regex


	print("\n")
	return cwd, wildcard


#Hash all files with given parameters
def Scanfilesystem(folder, chf, regex):
	result = filehash.FileHash(chf).hash_dir(folder, regex) # Using filehash library to generating file hashes
	if len(result) == 0:
		print(f"\n\n{colors.red}{colors.bold}No files found, try again{colors.default}\n\n")
		exit()
	return result


#NSRL Lookup
def Queryhashedb(hashsums):
	"""
		TODO:
		https://github.com/sptonkin/nsrlsearch
		One way to do this is maybe host your own REST API webservice and host the files in the cloud then query from that
	"""
	webpage = curl("http://nsrl.hashsets.com/national_software_reference_library1_list.php?q=(MD5~equals~%s)" % hashsums).text # Webscrapers and bots forbidden, caution
	if "No results found." in webpage:
		return True
	else:
		return False


#Take in a file hash and query it to VirusTotal using your API token
def Queryvt(hashsums):
	scan = virus_total_apis.PublicApi(VT_ID).get_file_report(hashsums) # Max 500 a day at 4 per minute
	if scan['response_code'] == 200: # REST API check
		if scan['results']['response_code'] == 1: # True positives only
			return scan
#		elif scan['results']['response_code'] == 0: # If true negatives are needed otherwise None is returned
#			return scan
	elif scan['response_code'] == 204:
		exit(f"\n{colors.red}Concurrent API Rate Limit Reached{colors.default}\n")
	else:
		exit(f"\n{colors.red}API Error{colors.default}\n")
	

#Present any detections
def Report(responses, hashsums):
	if len(responses) == 0: # Check if theres nothing in this list considering None entries were filtered
		print(f"\n\n{colors.green}{colors.bold}No malicious files were detected\n{colors.default}")
	else:
		print(f"\n\n{colors.red}{colors.bold}Malicious files detected\n\n{colors.default}")
		print("File Reports: \n")
		for i in range(len(hashsums)): # Iterate through all scanned files
			for n in range(len(responses)): # Iterate through all scanned hashes
				if hashsums[i]['hash'] == responses[n]['results']['sha256']: # Compare and map VT hashes to their files. Hashsums[] may be smaller than Responses[].
					print(f"{colors.yellow}{hashsums[i]['file']}{colors.default}" + ": " + responses[n]['results']['sha256'] + "\t\t" + f"{colors.red}{str(responses[n]['results']['positives'])}/{str(responses[n]['results']['total'])}{colors.default}") # File: Hash - Score




if __name__ == "__main__":
    main()
