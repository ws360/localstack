import importlib
import logging
from functools import singledispatchmethod
from typing import Any, Dict, Protocol, TypedDict, runtime_checkable

from moto.core.utils import BackendDict

from localstack.services.stores import AccountRegionBundle

LOG = logging.getLogger(__name__)


class StateVisitor:
    def visit(self, state_container: Any):
        """
        Visit (=do something with) a given state container. A state container can be anything that holds service state.
        An AccountRegionBundle, a moto BackendDict, or a directory containing assets.
        """
        raise NotImplementedError


@runtime_checkable
class StateVisitable(Protocol):
    def accept(self, visitor: StateVisitor):
        """
        Accept a StateVisitor. The implementing method should call visit not necessarily on itself, but can also call
        the visit method on the state container it holds. The common case is calling visit on the stores of a provider.
        :param visitor: the StateVisitor
        """


class ServiceBackend(TypedDict):
    """Wrapper of the possible type of backends that a service can use."""

    localstack: AccountRegionBundle | None
    moto: BackendDict | Dict | None


class ServiceBackendCollectorVisitor:
    """Implementation of StateVisitor meant to collect the backends that a given service use to hold its state."""

    def __init__(self) -> None:
        self.store: AccountRegionBundle | None = None
        self.backend_dict: BackendDict | Dict | None = None

    @singledispatchmethod
    def visit(self, state_container: Any):
        raise NotImplementedError("Can't restore state container o type %s", type(state_container))

    @visit.register(AccountRegionBundle)
    def _(self, state_container: AccountRegionBundle):
        self.store = state_container

    @visit.register(BackendDict)
    def _(self, state_container: BackendDict):
        self.backend_dict = state_container

    def collect(self) -> ServiceBackend:
        return ServiceBackend(localstack=self.store, moto=self.backend_dict)


def _load_attribute_from_module(module_name: str, attribute_name: str) -> Any | None:
    """
    Attempts at getting an attribute from a given module.
    :return the attribute or None, if the attribute can't be found
    """
    try:
        module = importlib.import_module(module_name)
        return getattr(module, attribute_name)
    except (ModuleNotFoundError, AttributeError) as e:
        LOG.debug(
            'Unable to get attribute "%s" for module "%s": "%s"', attribute_name, module_name, e
        )
        return


class ReflectionStateLocator:
    """
    Implementation of the StateVisitable protocol that uses reflection to visit and collect anything that hold state
    for a service, based on the assumption that AccountRegionBundle and BackendDict are stored in a predictable
    location with a predictable naming.
    """

    provider: Any

    def __init__(self, provider: Any):
        self.provider = provider

    def accept(self, visitor: StateVisitor):
        service: str = self.provider.service.replace("-", "_")      # needed for services like cognito-idp

        # try to load AccountRegionBundle from predictable location
        attribute_name = f"{service}_stores"
        module_name = f"localstack_ext.services.{service}.models"

        # it first looks for a module in ext; eventually, it falls back to community
        attribute = _load_attribute_from_module(module_name, attribute_name)
        if attribute is None:
            attribute = _load_attribute_from_module(
                f"localstack.services.{service}.models", attribute_name
            )

        if attribute:
            visitor.visit(attribute)

        # try to load BackendDict from predictable location
        module_name = f"moto.{service}.models"
        attribute_name = f"{service}_backends"
        attribute = _load_attribute_from_module(module_name, attribute_name)

        if attribute:
            visitor.visit(attribute)
