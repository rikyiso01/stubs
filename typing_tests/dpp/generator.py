from datetime import date
from faker import Faker
import random
from dataclasses import dataclass, field
import networkx as nx
import matplotlib.pyplot as plt
from enum import StrEnum, auto


class Gender(StrEnum):
    MALE = auto()
    FEMALE = auto()
    NON_BINARY = auto()


GENDERS = {Gender.MALE: 0.45, Gender.FEMALE: 0.45, Gender.NON_BINARY: 0.45}


type ID = str


@dataclass(kw_only=True)
class User:
    username: ID  # EI
    name: str  # EI
    surname: str  # EI
    birth_date: date  # QI
    gender: str  # QI
    cap: int  # QI
    address: str  # QI
    city: str  # QI
    phone_number: str  # QI
    email: str  # EI
    following: set[ID] = field(default_factory=set)  # SD
    follower: set[ID] = field(default_factory=set)

    @property
    def age(self):
        return (date.today() - self.birth_date).days // 365

    def __hash__(self):
        return hash(self.username)


def random_gender() -> Gender:
    (result,) = random.choices(
        [*Gender], k=1, weights=[GENDERS[gender] for gender in Gender]
    )
    return result


def profile(faker: Faker):
    return User(
        username=faker.unique.user_name(),
        name=faker.name(),
        surname=faker.last_name(),
        birth_date=faker.date_of_birth(),
        gender=random_gender(),
        cap=int(faker.postcode()),
        address=faker.street_address(),
        city=faker.city(),
        phone_number=faker.unique.phone_number(),
        email=faker.unique.email(),
    )


def profiles(
    faker: Faker,
    n: int,
    seed: int,
    alpha: float,
    beta: float,
    gamma: float,
    delta_in: float,
    delta_out: float,
):
    profiles = [profile(faker) for _ in range(n)]
    G = nx.scale_free_graph(
        n=n,
        alpha=alpha,
        beta=beta,
        gamma=gamma,
        delta_in=delta_in,
        delta_out=delta_out,
    )
    for i, j in G.edges():
        if i == j:
            continue
        profiles[i].following.add(profiles[j].username)
        profiles[j].follower.add(profiles[i].username)
    return profiles


def profiles_to_graph(users: list[User]) -> dict[str, list[str]]:
    return {user.username: [*user.following] for user in users}


def plot_users(users: list[User]):
    graph = nx.DiGraph(profiles_to_graph(users))
    # pos = nx.spring_layout(graph)
    centrality = [*nx.closeness_centrality(graph).values()]
    nx.draw(graph, node_size=10, node_color=centrality, edge_color=(0.1, 0.5, 0.8, 0.3))
    # nx.draw(graph, pos, node_size=100, linewidths=0.01, margins=(0, 0))
    plt.savefig("result.png")
    graph.remove_edges_from(nx.selfloop_edges(graph))
