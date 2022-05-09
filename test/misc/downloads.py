#
# All credits to
#   https://stackoverflow.com/users/797495/pedro-lobito
#   https://stackoverflow.com/questions/4338358/github-can-i-see-the-number-of-downloads-for-a-repo
#

import requests

owner = "per2jensen"
repo = "dar-backup"
h = {"Accept": "application/vnd.github.v3+json"}
u = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100"
r = requests.get(u, headers=h).json()
r.reverse() # older tags first
for rel in r:
  if rel['assets']:
  	tag = rel['tag_name']
  	dls = rel['assets'][0]['download_count']
  	pub = rel['published_at']
  	print(f"Pub: {pub} | Tag: {tag} | Dls: {dls} ")