#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import logging

from collections import OrderedDict
from argparse import Namespace, ArgumentParser, RawTextHelpFormatter

logger = logging.getLogger(__name__)

__all__ = ("NestingNamespace", "TaskDriverArgumentParser", "Option",
           "Argument", "NestedConfig", "ProxyConfig", "SubCommand",
           "ConfigurableComponent", "TaskDriver")

class NestingNamespace(Namespace):

    def __setattr__(self, name, value):
        names = name.split(".")
        if len(names) > 1:
            parent = self
            for ns_name in names[:-1]:
                ns = getattr(parent, ns_name, NestingNamespace())
                # set it in case it did not exist
                setattr(parent, ns_name, ns)
                parent = ns
            setattr(parent, names[-1], value)
        else:
            super().__setattr__(name, value)

    def __getattr__(self, name):
        names = name.split(".")
        if len(names) > 1:
            ns = self
            for ns_name in names[:-1]:
                ns = getattr(ns, ns_name)
            return getattr(ns, names[-1])
        else:
            raise AttributeError("Attribute %s does not exist" % name)

    def flatten(self, ns=None):
        ns = ns or Namespace()
        for key,val in self.__dict__.items():
            if not isinstance(val, self.__class__):
                setattr(ns, key, val)
            else:
                val.flatten(ns)
        return ns

    def update(self, other):
        for k,v in other.__dict__.items():
            if isinstance(v, self.__class__) and hasattr(self, k):
                getattr(self, k).update(v)
            else:
                setattr(self, k, v)


class TaskDriverHelpFormatter(RawTextHelpFormatter):

    def _get_default_metavar_for_optional(self, action):
        return action.dest.split(".")[-1]

    def _get_default_metavar_for_positional(self, action):
        return action.dest.split(".")[-1]


class TaskDriverArgumentParser(ArgumentParser):
    """
    Argument parser for TaskDriver-based tools
    """

    def __init__(self, *args, **kwargs):
        if "formatter_class" not in kwargs:
            kwargs["formatter_class"] = TaskDriverHelpFormatter
        super().__init__(*args, **kwargs)
        self._subparsers_action = None

    def parse_args(self, args=None, namespace=None, **kwargs):
        if not namespace:
            namespace = NestingNamespace()
        return super().parse_args(args, namespace, **kwargs)

    def add_subparsers(self, *args, **kwargs):
        """
        argparse allows only a single subparser action object to be
        produced. This overrides the creation method so that the same
        instance is returned if multiple calls are made to avoid raising
        an exception in this case.
        """
        if self._subparsers_action is None:
            self._subparsers_action = super().add_subparsers(*args, **kwargs)
        return self._subparsers_action


class DriverConfigEntry:
    """Base element of declarative configuration options in driver classes"""

    def __init__(self, *args, **kwargs):
        """
        Arguments is the same as in :meth:`argparse.ArgumentParser.add_argument`
        except the first argument, the option name is inferred from
        the name of the option variable when the option is created in
        a :class:`TaskDriverComponent`
        """
        self.name = None
        self.args = args
        self.kwargs = kwargs

    @property
    def dest(self):
        return self.kwargs.get("dest", self.name)

    def make_config(self, parser, prefix="", keys=None, ns=None):
        """
        Add this configuration entry to an argparse argument parser

        :param parser: the parser to which the entry is added
        :type parser: :class:`TaskDriverArgumentParser`
        :param prefix: string specifying the namespace qualified name
        where the parsed configuration key is stored. (e.g. if 
        prefix="x.y.z" and name="mykey" the parser stores the value as
        args.x.y.z.mykey = <value>.
        :type prefix: string
        :param keys: opt-in list of keys to add to the parser, if no
        list is given, all keys are added.
        :type keys: iterable
        :param ns: namespace where the config entry default value should
        be added
        :type ns: :class:`NestingNamespace`
        :return: The default namespace where the item default has been added
        (see :param:`ns`)
        """
        if ns is None:
            ns = NestingNamespace()
        if keys and self.name not in keys:
            return ns
        self._make_argparse(parser, prefix)
        self._make_default(ns, prefix)
        return ns

    def _make_argparse(self, parser, prefix):
        """Add the config entry to an argparse parser"""
        pass

    def _make_default(self, ns, prefix):
        """Add the config entry to the default namespace"""
        setattr(ns, self.dest, self.kwargs.get("default", None))

    def __str__(self):
        return "<%s %s %s>" % (self.name, self.args, self.kwargs)


class Argument(DriverConfigEntry):
    """Configuration entry rendered as positional argument"""

    def _make_argparse(self, parser, prefix):
        name = prefix + self.dest
        args = (name,) + self.args
        parser.add_argument(*args, **self.kwargs)


class Option(DriverConfigEntry):
    """Configuration entry redered as optional argument"""

    def _make_argparse(self, parser, prefix):
        if prefix:
            kwargs = dict(self.kwargs)
            kwargs["dest"] = prefix + self.dest
        else:
            kwargs = self.kwargs
        args = ("--%s" % self.name,) + self.args
        parser.add_argument(*args, **kwargs)


class NestedConfig(DriverConfigEntry):

    def __init__(self, nested):
        super().__init__()
        self.nested = nested

    def make_config(self, parser, prefix="", keys=None, ns=None):
        if ns is None:
            ns = NestingNamespace()
        nested_ns = NestingNamespace()
        setattr(ns, self.name, nested_ns)
        if keys and self.name not in keys:
            return ns
        prefix += "%s." % self.name
        model = self.nested.get_config_model()
        return model.make_config(parser, prefix=prefix, ns=nested_ns)

    def __str__(self):
        return "<%s %s>" % (self.name, self.nested.get_config_model())


class ProxyConfig(DriverConfigEntry):
    """
    Special configuration entry that wraps multiple other entries without
    requiring a new ConfigurableComponent as input
    """

    def __init__(self, *args, **kwargs):
        """
        A proxy config acts as a configuration items container.
        The constructor accepts variable number of initialized
        DriverConfigEntry elements or keyword arguments of
        uninitialized DriverConfigEntry elements that are
        added to the proxy entry with the given name.
        """
        super().__init__()
        self.nested = OrderedDict()
        for opt in args:
            self.nested[opt.name] = opt
        for k,opt in kwargs.items():
            self.add_option(k, opt)

    def add_option(self, name, option):
        """
        Add a new option to the configuration.

        :param option: the option to be added
        :type option: :class:`DriverConfigEntry`
        """
        option.name = name
        self.nested[name] = option

    def make_config(self, parser, prefix="", keys=None, ns=None):
        if ns is None:
            ns = NestingNamespace()
        for k,opt in self.nested.items():
            if keys and k not in keys:
                continue
            opt.make_config(parser, prefix=prefix, ns=ns)
        return ns

    def __str__(self):
        config_entries = "<"
        for opt in self.nested.values():
            config_entries += repr(opt) + ", "
        config_entries += ">"
        return config_entries


class SubCommand(DriverConfigEntry):

    def __init__(self, nested=None, **kwargs):
        super().__init__(**kwargs)
        if nested is None:
            # empty config element, so we can define a subcommand without
            # having a separate config object for it, if it is not required
            nested = ConfigurableComponent
        self.nested = nested

    def make_config(self, parser, prefix="", keys=None, ns=None):
        if ns is None:
            ns = NestingNamespace()
        nested_ns = NestingNamespace()
        setattr(ns, self.name, nested_ns)
        subparser = parser.add_subparsers()
        subcommand = subparser.add_parser(self.name, *self.args, **self.kwargs)
        # make sure subparser namespace is created even with subcommands with
        # no arguments/options
        prefix += "%s." % self.name
        subcommand_parsed_arg = "%s_subcommand_%s" % (prefix, self.name)
        subcommand.set_defaults(**{subcommand_parsed_arg: True})
        model = self.nested.get_config_model()
        return model.make_config(subcommand, prefix=prefix, ns=nested_ns)

    def __str__(self):
        return "<%s %s>" % (self.name, self.nested.get_config_model())


class DriverConfig(ProxyConfig):
    """
    Driver configuration object, this can be used to produce
    a dict of configuration items or an argument parser
    with options for all configuration items.
    """

    def __iter__(self):
        for keyopt in self.nested.items():
            yield keyopt

    def update(self, other):
        """
        Merge another configuration in this one.
        The keys of the merged conf object are
        shadowed by the ones in this conf object.
        """
        merge_opts = dict(other.nested)
        merge_opts.update(self.nested)
        self.nested = merge_opts


class TaskDriverType(type):
    """
    Type of the TaskDriver.
    Initialize the declarative component configuration into
    an instance attribute where the configuration options will be resolved.
    """

    def __new__(cls, name, bases, attrs, **kwargs):
        config = DriverConfig()
        for k,v in list(attrs.items()):
            if isinstance(v, DriverConfigEntry):
                del attrs[k]
                config.add_option(k, v)
        for base in bases:
            if hasattr(base, "_config_model"):
                config.update(base._config_model)
        new_instance = super().__new__(cls, name, bases, attrs, **kwargs)
        new_instance._config_model = config
        return new_instance


class ConfigurableComponent(metaclass=TaskDriverType):
    """
    Base interface of configurable components.
    Configs are used to parametrize all elements (parser, transforms etc)
    they are merged by the init of the driver and by the task metaclass to
    generate the argparse tool options if needed. The argparse object is
    propagated back in the config to the inits of all the components.
    """
    description = ""

    @classmethod
    def get_config_model(cls):
        """Get the config model created by the metaclass"""
        return cls._config_model

    @classmethod
    def make_config(cls, parser, keys=None):
        """
        Setup a new configuration

        :param parser: an argument parser
        :type parser: :class:`argparse.ArgumentParser`
        :param keys: include only the given options in the config
        :type keys: iterable
        :return: a namespace with the default configuration
        """
        return cls._config_model.make_config(parser, keys=keys)

    def __init__(self, **kwargs):
        """
        Initialize a configurable element with a configuration object

        :param config: a configuration namespace object
        :type config: :class:`NestingNamespace`
        """
        try:
            self.config = kwargs.pop("config")
        except KeyError as e:
            logger.error("Missing required argument: config")
            raise
        super().__init__(**kwargs)

    def update_config(self, config):
        """
        Update the configuration based on the given configuration object.
        Note that the new configuration is not required/guaranteed to
        specify a value for all the options in the main configuration
        so we simply do a merge here.

        :param config: the configuration from which to update from
        :type config: :class:`NestingNamespace`
        """
        if self.config:
            self.config.update(config)
        else:
            self.config = config


class TaskDriver(ConfigurableComponent):
    """
    The driver components abstract the configuration options of
    tasks allowing to specify options in a single place.
    The task driver is the base class for plots
    and tools that use the cheriplot parsers, datasets
    and plotting tools.

    This defines the interface for runnable tasks with a configuration.
    """

    def run(self):
        """This method should be overridden in subclasses"""
        raise NotImplementedError("Abstract method")
