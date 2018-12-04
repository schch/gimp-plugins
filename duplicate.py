#!/usr/bin/env python

from gimpfu import *

def python_duplicate(timg, tdrawable, columns, rows):
    width = tdrawable.width
    height = tdrawable.height
    n = int(columns)
    m = int(rows)

    tmpImg = pdb.gimp_image_duplicate(timg)
    tmpImg.disable_undo()
    tmpImg.flatten()
    tmpImg.merge_visible_layers(CLIP_TO_IMAGE)

    dupImg = gimp.Image(n*width, m*height, pdb.gimp_image_base_type(timg));
    dupImg.disable_undo()

    tmpLayer = pdb.gimp_layer_new_from_drawable(tmpImg.active_layer, dupImg)
    tmpLayer.mode = NORMAL_MODE
    layer_name = tmpImg.active_layer.name
    pdb.gimp_image_delete(tmpImg)

    for i in range(n):
        for j in range(m):
            layer = pdb.gimp_layer_new_from_drawable(tmpLayer, dupImg)
            dupImg.add_layer(layer, 0)
            layer.mode= NORMAL_MODE
            pdb.gimp_layer_translate(layer, i*width, j*height)

    dupImg.flatten()
    dupImg.merge_visible_layers(CLIP_TO_IMAGE)
    dupImg.active_layer.name = layer_name + " " + str(m) + "x" + str(n)

    pdb.gimp_display_new(dupImg)
    gimp.displays_flush()

register(
        "pyduplicate",
        "Duplicate Image to MxN matrix",
        "Duplicate Image to MxN matrix",
        "Christoph Schneider <christoph.schneider@gmx.net>",
        "Christoph Schneider",
        "2018-12-02",
        "<Image>/Image/pyDuplicate",
        "*",
        [(PF_SPINNER, "columns", "Number of columns", 2, (1,10,1)),
         (PF_SPINNER, "rows", "Number of rows", 2, (1,10,1))],
        [],
        python_duplicate)

main()
