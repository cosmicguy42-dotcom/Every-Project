
from manim import *

class yoink(Scene):
    def scene(self):
        
        t = Text("Hi")
        self.play(Write(t))

