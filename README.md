# secsplit
An alpha document splitter. It's new, so it's nearly guaranteed to be insecure.

Actually, we don't even obscure the password field (it's a command line argument), so it is *not* ready for production.

You have been warned.


# What's the use of it?

You can seperate documents out to different physical (or digital) locations. Assuming that the physical/digital locations have perfect security, it wouldn't matter if the AES algorithm breaks, since XOR one time pads provide theoretically perfect security.


# How do I use this thing?

## Structure

Let's go over the structure a little bit first. The document is the file which you're splitting into shards.

So you essentially have this:

* Create shards from the original document, that recreate the original document when xor'd together
* Encrypt shards with AES-GCM
* Encrypt the key used for the above step (the shard key) with a key derived from a password using PBKDF2-SHA512 (the master key)


## Generating a new shard key  

Firstly, you'll need to generate a new shard key, and encrypt that with a password. You can do that by running this command:
```bash
secsplit genkey -p <your password> -o <shard key output path>
```

For example:
```bash
secsplit genkey -p jupiter -o ~/reportshard/secsplit.skey
```

Note that the salt, iv, and the actual key changes each time you run the command, even if the password is the same.


## Sharding a document

Now that you have a shard key generated, you can now shard a document by using this command:
```bash
secsplit shard -p <your password> -k <shard key file> -i <document path> -o <shard path> <shard path> ...
```
Where `...` indicates that you can supply as many shards as you want. Note that you must supply at least two paths to save shards in.

For example:
```bash
secsplit shard -p jupiter -k ~/reportshard/secsplit.skey -i ~/Documents/report.pdf -o ~/reportshard/shards/1.shard ~/reportshard/shards/2.shard ~/reportshard/shards/3.shard
```


## Merging back

Ok. So you've got the shards, and now you want to use them to recreate your document (after you probably used a command like `shred` on it). You can merge shards back into the document like so:
```bash
secsplit merge -p <your password> -o <shard key file> -i <shard path> <shard path> ... -o <merge output path>
```

For example:
```bash
secsplit merge -p jupiter -o ~/reportshard/secsplit.skey -i ~/reportshard/shards/1.shard ~/reportshard/shards/2.shard ~/reportshard/shards/3.shard -o ~/Documents/merged-report.pdf
```

If you don't see your original file, you're missing a shard somewhere.


## Subsharding

You've now realised that you want additional shards. Rather treating the shard as another document, you can actually reshard. This will unencrypt the shard, and then create additional files, like so:
```bash
secsplit reshard -p <your password> -k <shard key file> -i <original shard> -o <subshard path> <subshard path> ...
```
Again, `...` indicates that you can supply as many shards as you want, but you must still have a minimum of two.

For example:
```bash
secsplit reshard -p jupiter -l ~/reportshard/secsplit.skey -i ~/reportshard/shards/3.shard -o ~/reportshard/shards/3sub1.shard ~/reportshard/shards/3sub2.shard
shred -n 200 -z -u ~/reportshard/shards/3.shard && mv ~/reportshard/shards/3sub1.shard ~/reportshard/shards/3.shard && mv ~/reportshard/shards/3sub2.shard ~/reportshard/shards/4.shard # SEE NOTES BELOW BEFORE RUNNING THIS LINE
```
Note that we use shred to delete the original shard. You should only do this once you're sure that the new shards work, but you should be sure to do this (else the new shards are effectively bypassed by the old one).

Also, note that you should *not* include both the original shard and the subshards when merging, as the subshards xor together to make the original shard.


## Changing your password

You can change your password by using the following command:
```bash
secsplit chpass -p <old password> -n <new password> -k <old shard key location> -o <new shard key location>
```

For example:
```bash
secsplit chpass -p jupiter -n mercury -k ~/reportshard/secsplit.skey -o ~/reportshard/new.skey
shred -n 200 -z -u ~/reportshard/secsplit.skey && mv ~/reportshard/new.skey ~/reportshard/secsplit.skey # Again, run this only once you're sure that the above has worked
```

You could also use this (although this is more risky):
```bash
secsplit chpass -p jupiter -n mercury -k ~/reportshard/secsplit.skey -o ~/reportshard/secsplit.skey
```

## Regenerating the master key

You can regenerate the master key by simply regenerating the salt, and to do that, you can simply run:
```bash
secsplit chpass -p <password> -n <password> -k <old shard key location> -o <new shard key location>
shred -n 200 -z -u <old shard key location> # Yet again, only run this once you know the above has worked
```

For example:
```bash
secsplit chpass -p jupiter -n jupiter -k ~/reportshard/secsplit.skey -o ~/reportshard/new.skey
shred -n 200 -z -u ~/reportshard/secsplit.skey && mv ~/reportshard/new.skey ~/reportshard/secsplit.skey
```

Or for a more risky approach:
```bash
secsplit chpass -p jupiter -n jupiter -k ~/reportshard/secsplit.skey -o ~/reportshard/secsplit.skey
```

# I have an error

The argument checking currently consists of a simple validator, and doesn't report which argument is missing/faulty, so secsplit gives very generic errors most of the time. I'll fix this soon.

At the moment could you file an issue to let me know what command that you were running which isn't working as you expect, please?

# Your code style is awful

I know.
