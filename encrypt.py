#!/usr/bin/env python

from array import array
import random
from binascii import hexlify 
from binascii import unhexlify 
from os import urandom as sysrandom
import hashlib
import hmac
from gimpfu import *

# HMAC_DRBG taken from https://github.com/fpgaminer/python-hmac-drbg
# Implements an HMAC_DRBG (NIST SP 800-90A) based on HMAC_SHA256.
# Supports security strengths up to 256 bits.
# Parameters are based on recommendations provided by Appendix D of NIST SP 800-90A.
class HMAC_DRBG (object):
	def __init__ (self, entropy, requested_security_strength=256, personalization_string=b""):
		if requested_security_strength > 256:
			raise RuntimeError ("requested_security_strength cannot exceed 256 bits.")

		# Modified from Appendix D, which specified 160 bits here
		if len (personalization_string) * 8 > 256:
			raise RuntimeError ("personalization_string cannot exceed 256 bits.")

		if requested_security_strength <= 112:
			self.security_strength = 112
		elif requested_security_strength <= 128:
			self.security_strength = 128
		elif requested_security_strength <= 192:
			self.security_strength = 192
		else:
			self.security_strength = 256

		if (len (entropy) * 8 * 2) < (3 * self.security_strength):
			raise RuntimeError ("entropy must be at least %f bits." % (1.5 * self.security_strength))

		if len (entropy) * 8 > 1000:
			raise RuntimeError ("entropy cannot exceed 1000 bits.")

		self._instantiate (entropy, personalization_string)
	

	# Just for convenience and succinctness
	def _hmac (self, key, data):
		return hmac.new (key, data, hashlib.sha256).digest ()
	

	def _update (self, provided_data=None):
		self.K = self._hmac (self.K, self.V + b"\x00" + (b"" if provided_data is None else provided_data))
		self.V = self._hmac (self.K, self.V)

		if provided_data is not None:
			self.K = self._hmac (self.K, self.V + b"\x01" + provided_data)
			self.V = self._hmac (self.K, self.V)
	

	def _instantiate (self, entropy, personalization_string):
		seed_material = entropy + personalization_string

		self.K = b"\x00" * 32
		self.V = b"\x01" * 32

		self._update (seed_material)
		self.reseed_counter = 1
	
	
	def reseed (self, entropy):
		if (len (entropy) * 8) < self.security_strength:
			raise RuntimeError ("entropy must be at least %f bits." % (self.security_strength))

		if len (entropy) * 8 > 1000:
			raise RuntimeError ("entropy cannot exceed 1000 bits.")

		self._update (entropy)
		self.reseed_counter = 1
	

	def generate (self, num_bytes, requested_security_strength=256):
		if (num_bytes * 8) > 7500:
			raise RuntimeError ("generate cannot generate more than 7500 bits in a single call.")

		if requested_security_strength > self.security_strength:
			raise RuntimeError ("requested_security_strength exceeds this instance's security_strength (%d)" % self.security_strength)

		if self.reseed_counter >= 10000:
			return None

		temp = b""

		while len (temp) < num_bytes:
			self.V = self._hmac (self.K, self.V)
			temp += self.V

		self._update (None)
		self.reseed_counter += 1

		return temp[:num_bytes]

# transform black and white drawable to "xorable" image
# i.e. transform a singe pixel to a black and white
# 2x2 pattern with b denoting black an w denoting  white
# b -> bw         w -> wb
#      wb              bw
# this transforms xor into an addition of two of these patterns
# whith b+b = b, w+w = w, b+w = w+b = b
#
# xor | 0 1        | bw | wb
# ----------     + | wb | bw
#   0 | 0 1    --------------
#   1 | 1 0     bw | bw | bb
#               wb | wb | bb
#               ---|---------
#               wb | bb | wb
#               bw | bb | bw
#
# returns new image with a singe layer containing the transformed drawable
# pixel_width:    size of one part of the 2x2 block i.e. 1 pixel is transformed
#                 to a 4*pixel_width block
# boundary:       number of white pixels around the transformed image
# name:           name for the transformed image
# lablelOnBottom: flag to indicate where on the final image to place name
def python_encrypt_transform(drawable, pixel_width, boundary, 
                             name, labelOnBottom):
    pw = pixel_width
    bdry = boundary * 2
    bw = 2 * 2

    width = drawable.width * pw * 2
    height = drawable.height * pw * 2

    img = gimp.Image(width+bdry, height+bdry, GRAY)
    img.disable_undo()

    #border layer
    layer = gimp.Layer(img, name, width+bw, height+bw, GRAY_IMAGE,
                           100, NORMAL_MODE)
    img.add_layer(layer, 0)
    pdb.gimp_layer_translate(layer, bdry/2-bw/2, bdry/2-bw/2)
    pdb.gimp_edit_fill(layer, WHITE_FILL)
    pdb.gimp_invert(layer)
    pdb.gimp_layer_resize_to_image_size(layer)

    #text border layer
    txtBorder = gimp.Layer(img, name, width+bw, bdry/2, GRAY_IMAGE,
                           100, NORMAL_MODE)
    img.add_layer(txtBorder, 0)
    pdb.gimp_edit_fill(txtBorder, WHITE_FILL)
    pdb.gimp_invert(txtBorder)
    pdb.gimp_item_set_linked(txtBorder, TRUE)

    txtBorderFill = gimp.Layer(img, name, width, bdry/2-bw, GRAY_IMAGE,
                           100, NORMAL_MODE)
    img.add_layer(txtBorderFill, 0)
    pdb.gimp_edit_fill(txtBorderFill, WHITE_FILL)
    pdb.gimp_layer_translate(txtBorderFill, bw/2, bw/2)
    pdb.gimp_item_set_linked(txtBorderFill, TRUE)

    # black and white pattern destination layer
    layer = gimp.Layer(img, name, width, height, GRAY_IMAGE,
                           100, NORMAL_MODE)
    img.add_layer(layer, 0)
    pdb.gimp_edit_fill(layer, WHITE_FILL)

    max_progress = drawable.width * drawable.height
    gimp.progress_init("transforming " + name + " ...")
    src_rgn = drawable.get_pixel_rgn(0, 0, drawable.width, drawable.height, 
                                     FALSE, FALSE)
    dst_rgn = layer.get_pixel_rgn(0, 0, layer.width, layer.height, TRUE, FALSE)

    BLACK = "".join(map(chr, array('B', [0]*(dst_rgn.bpp*pw*pw))))

    for x in range(0, drawable.width):
        dst_x = x * pw * 2
        for y in range(0, drawable.height):
            dst_y = y * pw * 2

            if ord(src_rgn[x,y][0]) == 0:
                if pw > 1:
                    dst_rgn[dst_x:dst_x+pw , dst_y:dst_y+pw] = BLACK
                    dst_rgn[dst_x+pw:dst_x+2*pw , dst_y+pw:dst_y+2*pw] = BLACK
                else:
                    dst_rgn[dst_x, dst_y] = BLACK
                    dst_rgn[dst_x+pw, dst_y+pw] = BLACK
            else:
                if pw > 1:
                    dst_rgn[dst_x+pw:dst_x+2*pw, dst_y:dst_y+pw] = BLACK
                    dst_rgn[dst_x:dst_x+pw, dst_y+pw:dst_y+2*pw] = BLACK
                else:
                    dst_rgn[dst_x+pw, dst_y] = BLACK
                    dst_rgn[dst_x, dst_y+pw] = BLACK

        gimp.progress_update( float(x*y) / max_progress )

    pdb.gimp_progress_end()

    pdb.gimp_layer_translate(layer, bdry/2, bdry/2)
    
    txtLayer = pdb.gimp_text_layer_new(img, name, "Sans", bdry/2-bw/2, 0)
    img.add_layer(txtLayer, 0)
    pdb.gimp_layer_translate(txtLayer, bw/2+1, -5)
    pdb.gimp_item_set_linked(txtLayer, TRUE)
    if labelOnBottom:
        pdb.gimp_layer_translate(txtLayer,
                                 bdry/2-bw/2, 
                                 # layer.width/2+bdry/2+bw/2, 
                                 layer.height + bdry/2)
    else:
        pdb.gimp_layer_translate(txtLayer, bdry/2-bw/2, 0)

    img.merge_visible_layers(CLIP_TO_IMAGE)
    img.flatten
    return img

def python_encrypt_create_key(version=0):
    try:
        keybytes = sysrandom(32)
    except NotImplementedError:
        import time
        keybytes = hashlib.sha256(str(time.time())).digest()
        print "Warning: Can't access urandom. Used random numbers are not safe."

    return keybytes

def python_encrypt_create_seed_from_key(keybytes, version=0):
    salt = str(version) + hashlib.sha256(keybytes).hexdigest()
    seed = hashlib.pbkdf2_hmac("sha256", keybytes, salt, 1000, 64)
    return seed

def python_encrypt_randomize_with_key(drawable, keybytes, version=0):
    seed = python_encrypt_create_seed_from_key(keybytes, version)
    myrandom = HMAC_DRBG(seed, 128)
    python_encrypt_randomize_with_random(drawable, myrandom, seed, version)

def python_encrypt_randomize_without_key(drawable, version=0):
    keybytes = sysrandom(32)
    myrandom = HMAC_DRBG(keybytes, 128)
    python_encrypt_randomize_with_random(drawable, myrandom, None, version)
    return keybytes

def python_encrypt_randomize_with_random(drawable, myrandom, seed=None, version=0):
    myseed = seed
    max_progress = drawable.width * drawable.height
    gimp.progress_init("generating key image ...")
    rgn = drawable.get_pixel_rgn(0, 0, drawable.width, drawable.height, 
                                 TRUE, FALSE)
    BLACK = "".join(map(chr, array('B', [0]*(rgn.bpp))))
    WHITE = "".join(map(chr, array('B', [255]*(rgn.bpp))))

    black_counter = 0
    for x in range(0, drawable.width):
        for y in range(0, drawable.height):
            rnd = myrandom.generate(1, 128)
            if rnd == None:
                if myseed == None:
                    myrandom.reseed(sysrandom(32))
                else:
                    myseed=python_encrypt_create_seed_from_key(myseed, version)
                    myrandom.reseed(myseed)
                rnd = myrandom.generate(1, 128)
            if ord(rnd) & 0x1:
                rgn[x,y] = BLACK
                black_counter = black_counter + 1
            else:
                rgn[x,y] = WHITE

        gimp.progress_update( float(x*y) / max_progress )
        
    drawable.flush()
    pdb.gimp_progress_end()
    #print "black: " + str(100.0 * black_counter / max_progress) + "%"

# main function called from gimp
def python_encrypt(timg, tdrawable,
                   invert=FALSE,
                   boundarywidth=30,
                   pixelwidth=5,
                   randomkey=TRUE,
                   userkey=None):
    width = tdrawable.width
    height = tdrawable.height

    if userkey != None and len(userkey) > 0 and len(userkey) != 64:
        print "invalid key of length: " + str(len(userkey)) + " != 32"
        return

    pdb.gimp_context_push()
    
    encImg = pdb.gimp_image_duplicate(timg)
    encImg.disable_undo()
    encImg.flatten()
    encImg.merge_visible_layers(CLIP_TO_IMAGE)
    pdb.gimp_threshold(encImg.active_layer, 127, 255)
    # inverted logic as a xor b = (a or !b) and (!a or b) and b is the original image
    if invert == FALSE:
        pdb.gimp_invert(encImg.active_layer)
    encImg.active_layer.name = "clear text (inverted)"
    invClearText = encImg.active_layer

    keyLayer = gimp.Layer(encImg, "encryption key", width, height, GRAY_IMAGE,
                           100, NORMAL_MODE)
    encImg.add_layer(keyLayer, 0)
    pdb.gimp_edit_fill(keyLayer, WHITE_FILL)
    keyLayer.mode = MULTIPLY_MODE

    version = 0
    mykey = b"";
    if userkey != None and len(userkey) == 64:
        mykey = unhexlify(userkey)
        python_encrypt_randomize_with_key(keyLayer, mykey)
    else:
        if randomkey == TRUE:
            mykey = python_encrypt_randomize_without_key(keyLayer)
        else:
            mykey = python_encrypt_create_key()
            python_encrypt_randomize_with_key(keyLayer, mykey, version)

    hexkey = hexlify(mykey).upper()
    keyhexdigest = hashlib.sha256(hexkey).hexdigest().upper()
    keyid = keyhexdigest[32-16:32]
    
    prettyHexkey = ""
    if randomkey == FALSE:
        prettyHexkey = " ".join(hexkey[i:i+4] for i in range(0,len(hexkey),4))
    
    keyImg = gimp.Image(width, height, GRAY)
    keyImg.disable_undo()
    tmpLayer = pdb.gimp_layer_new_from_drawable(keyLayer, keyImg)
    keyImg.add_layer(tmpLayer, 0)
    tmpLayer.mode= NORMAL_MODE
    tmpLayer.name = "encryption key"
    keyImg.flatten()

    xorgroup = pdb.gimp_layer_group_new(encImg)
    encImg.add_layer(xorgroup, 0)
    xorgroup.name = "or (clear text) and not (key)"
    xorgroup.mode = ADDITION_MODE
    xorgroup.opacity = 100.0
    
    tmpLayer = invClearText.copy()
    pdb.gimp_image_insert_layer(encImg, tmpLayer, xorgroup, 0)
    pdb.gimp_invert(tmpLayer)
    tmpLayer.mode = NORMAL_MODE
    tmpLayer.name = "clear text"

    tmpLayer = keyLayer.copy()
    pdb.gimp_image_insert_layer(encImg, tmpLayer, xorgroup, 0)
    pdb.gimp_invert(tmpLayer)
    tmpLayer.mode = MULTIPLY_MODE
    tmpLayer.name = "key (inverted)"

    encImg.flatten()
    encImg.merge_visible_layers(CLIP_TO_IMAGE)
    encImg.active_layer.name = "encrypted image"

    pw = pixelwidth
    boundary = boundarywidth
    cipherTextTitle = "Cipher text to v" + str(version) + "_" + keyid
    transEnc = python_encrypt_transform(encImg.active_layer, pw, boundary, 
                                        cipherTextTitle, FALSE)
    pdb.gimp_image_delete(encImg)
    keyTitle = "Key (v" + str(version) + "_" + keyid + ") " + prettyHexkey
    transKey = python_encrypt_transform(keyImg.active_layer, pw, boundary, 
                                        keyTitle, TRUE)
    pdb.gimp_image_delete(keyImg)

    pdb.gimp_context_pop()
    
    pdb.gimp_display_new(transEnc)
    pdb.gimp_display_new(transKey)
    gimp.displays_flush()

register(
        "pyencrypt",
        "Encrypt B&W image using a random key",
        "Creates two images, one for the key and one for the encrypted image. Decryption is done by multipling the images or by printing on transparencies and overlaying the printouts. The original image is scaled by 2 times the pixel width in every direction. A 163x112 image will be scaled to A6@300ppi.",
        "Christoph Schneider <christoph.schneider@gmx.net>",
        "Christoph Schneider <christoph.schneider@gmx.net>",
        "2018-12-03",
        "<Image>/Filters/Noise/pyEncrypt",
        "GRAY*",
        [
                (PF_BOOL, "invert", "invert original image (usefull for QR-Codes)", FALSE),
                (PF_INT, "boundarywidth", "width of boundary", 30),
                (PF_INT, "pixelwidth", "size of a black or white block", 5),
                #        (PF_BOOL, "randomkey", "use a random seed instead of a key for seed creation", TRUE),
                #        (PF_STRING, "userkey", "use this 64 character hexstring as key for seed creation", "")
        ],
        [],
        python_encrypt)

main()
