
from dataclasses import dataclass

@dataclass
class Guy:
    name: str
    age: int
    is_a_guy: bool

    def __post_init__(self):
        if self.age <= 0:
            raise ValueError("age cannot be negative")




Person1 = Guy("Jonh", 34, True)
Person2 = Guy("BOB", 100, False)


print(Person1)
print(Person2)

