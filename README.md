# secsplit
An alpha document splitter. It's new, so it's nearly guaranteed to be insecure.

You have been warned.

# Notices

1. *IMPORTANT:* If you have created shards before version 0.3.0, you'll need to continue using the latest legacy structure version (0.2.0), or reshard your document. The latter is preferred, as the new version attempts to hide the length of your document a little better.
2. Passwords are now prompted for, and the command line option has been removed for security. You'll be prompted for these passwords.

# What's the use of it?

You can seperate documents out to different physical (or digital) locations. Assuming that the physical/digital locations have perfect security, it wouldn't matter if the AES algorithm breaks, since XOR one time pads provide theoretically perfect security.

# Installing

You can install it like:
```bash
npm install -g secsplit
```

# How do I use this thing?

## Structure

Let's go over the structure a little bit first. The document is the file which you're splitting into shards.

So you essentially have this:

* Create shards from the original document (with some added junk random data), that recreate the original document when xor'd together
* Encrypt shards with AES-GCM
* Encrypt the key used for the above step (the shard key) with a key derived from a password using PBKDF2-SHA512 (the master key)


## Generating a new shard key  

Firstly, you'll need to generate a new shard key, and encrypt that with a password. You can do that by running this command (and entering your desired password when prompted for it):
```bash
secsplit genkey -o <shard key output path>
```

For example:
```bash
secsplit genkey -o ~/reportshard/secsplit.skey
```

Note that the salt, iv, and the actual key changes each time you run the command, even if the password is the same.


## Sharding a document

Now that you have a shard key generated, you can now shard a document by using this command:
```bash
secsplit shard -k <shard key file> -i <document path> -o <shard path> <shard path> ...
```
Where `...` indicates that you can supply as many shards as you want. Note that you must supply at least two paths to save shards in.

You'll be prompted for your password that you set when generating the key file.

For example:
```bash
secsplit shard -k ~/reportshard/secsplit.skey -i ~/Documents/report.pdf -o ~/reportshard/shards/1.shard ~/reportshard/shards/2.shard ~/reportshard/shards/3.shard
```

You can also modify how much junk random data is added to your document (which is removed when you merge), like so:
```bash
secsplit shard -k <shard key file> -i <document path> -o <shard path> <shard path> ... -j <maximum amount of junk to add> -m <minimum amount of junk to add>
```

For example:
```bash
secsplit shard -k ~/reportshard/secsplit.skey -i ~/Documents/report.pdf -o ~/reportshard/shards/1.shard ~/reportshard/shards/2.shard ~/reportshard/shards/3.shard -m 100 -j 1100
```
This will add a random amount of bytes (but between 100 and 1100 bytes inclusive) to your document _whilst encrypted_. This will not affect your document when unencrypted/merged together.

Note that if unspecified, the default values are `minimum = 0` and `maximum = 1000`.


## Merging back

Ok. So you've got the shards, and now you want to use them to recreate your document (after you probably used a command like `shred` on it). You can merge shards back into the document like so:
```bash
secsplit merge -o <shard key file> -i <shard path> <shard path> ... -o <merge output path>
```

For example:
```bash
secsplit merge -o ~/reportshard/secsplit.skey -i ~/reportshard/shards/1.shard ~/reportshard/shards/2.shard ~/reportshard/shards/3.shard -o ~/Documents/merged-report.pdf
```

If you don't see your original file, you're missing a shard somewhere.


## Subsharding

You've now realised that you want additional shards. Rather treating the shard as another document, you can actually reshard. This will unencrypt the shard, and then create additional files, like so:
```bash
secsplit reshard -k <shard key file> -i <original shard> -o <subshard path> <subshard path> ...
```
Again, `...` indicates that you can supply as many shards as you want, but you must still have a minimum of two.

For example:
```bash
secsplit reshard -k ~/reportshard/secsplit.skey -i ~/reportshard/shards/3.shard -o ~/reportshard/shards/3sub1.shard ~/reportshard/shards/3sub2.shard
shred -n 200 -z -u ~/reportshard/shards/3.shard && mv ~/reportshard/shards/3sub1.shard ~/reportshard/shards/3.shard && mv ~/reportshard/shards/3sub2.shard ~/reportshard/shards/4.shard # SEE NOTES BELOW BEFORE RUNNING THIS LINE
```
Note that we use shred to delete the original shard. You should only do this once you're sure that the new shards work, but you should be sure to do this (else the new shards are effectively bypassed by the old one).

Also, note that you should *not* include both the original shard and the subshards when merging, as the subshards xor together to make the original shard.

## Gluing back together

Ok so I made a mistake and created too many shards for one of my files. Rather than regenerating the whole sharding process, I added the ability to glue shards back together.

You can do so like this:
```bash
secsplit glue -k <shard key file> -i <subshard path> <subshard path> ... -o <merged shard>
```

For example:
```bash
secsplit glue -k ~/reportshard/secsplit.skey -i ~/reportshard/shards/3.shard ~/reportshard/shards/4.shard -o ~/reportshard/shards/3merge.shard
shred -n 200 -z -u ~/reportshard/shards/3.shard && shred -n 200 -z -u ~/reportshard/shards/4.shard && mv ~/reportshard/shards/3merge.shard ~/reportshard/shards/3.shard
```

## Changing your password

You can change your password by using the following command:
```bash
secsplit chpass -k <old shard key location> -o <new shard key location>
```

You should enter your old password, and desired new password when prompted.

For example:
```bash
secsplit chpass -k ~/reportshard/secsplit.skey -o ~/reportshard/new.skey
shred -n 200 -z -u ~/reportshard/secsplit.skey && mv ~/reportshard/new.skey ~/reportshard/secsplit.skey # Again, run this only once you're sure that the above has worked
```

You could also use this (although this is more risky):
```bash
secsplit chpass -k ~/reportshard/secsplit.skey -o ~/reportshard/secsplit.skey
```

Note that you can set the same password to regenerate the salt, and therefore the master key.

# I have an error

The argument checking currently consists of a simple validator, and doesn't report which argument is missing/faulty, so secsplit gives very generic errors most of the time. I'll fix this soon.

At the moment could you file an issue to let me know what command that you were running which isn't working as you expect, please?

# Your code style is awful

I know.
