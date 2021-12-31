#!/usr/bin/env/ python

from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont

im1 = Image.open(r"C:\Users\lf\Desktop\testpillow.png")
image1 = im1.resize((450,400))

im2 = Image.open(r"C:\Users\lf\Desktop\zkxadesk.png")
image2 = im2.resize((450,400))


#save picture
# image.save(r"C:\Users\lf\Desktop\testpillow1.png")


# color spilt
im3 = Image.Image.split(image1)
im4 = Image.Image.split(image2)
#r.show()
#g.show()
#b.show()
# im1[0].show()
# im1[1].show()
# im1[2].show()
# im1[0].save(r"C:\Users\lf\Desktop\testpillow3.png")
# im1[1].save(r"C:\Users\lf\Desktop\testpillow4.png")
# im1[2].save(r"C:\Users\lf\Desktop\testpillow5.png")
 

 
#add water print 
# draw = ImageDraw.Draw(im)
# draw.rectangle((50,100,100,150),fill=(0,255,0),outline=(0,0,0))
# font=ImageFont.truetype('C:/Windows/Fonts/msyh.ttc',size=36)
# draw.text(xy=(200,200),text='test',fill=(255,0,0,18),font=font)
 
im_3 = Image.merge('RGB',[im4[0],im3[1],im4[2]])
#im.show()
im_3.show()
# im.save(r"C:\Users\lf\Desktop\testpillow56.png")