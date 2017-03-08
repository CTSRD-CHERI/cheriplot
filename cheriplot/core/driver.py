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

from argparse import Namespace

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
            print("getattr", name)
            ns = self
            for ns_name in names[:-1]:
                ns = getattr(ns, ns_name)
            return getattr(ns, names[-1])
        else:
            raise AttributeError("Attribute %s does not exist" % name)

class Argument:
    """Encapsulate an single simple option."""

    def __init__(self, *args, **kwargs):
        """
        Arguments is the same as in :meth:`argparse.ArgumentParser.add_argument`
        except the first argument, the option name is inferred from
        the name of the option variable when the option is created in
        a :class:`TaskDriverComponent`
        """
        self.args = args
        self.kwargs = kwargs

    def set_config(self, option_dict, name):
        option_dict[name] = self

    def as_argparse(self, name, parser, subparser, prefix=""):
        if prefix:
            self.kwargs["metavar"] = self.kwargs.get("metavar", name)
            name = prefix + name
        self.args = (name,) + self.args
        parser.add_argument(*self.args, **self.kwargs)

    def as_dict(self, name, option_dict):
        """
        Add this argument to an option dictionary of a config object

        :param name: The name is the name of the argument
        :type name: string
        :param option_dict: the target option dict
        :type option_dict: dict
        """
        value = self.kwargs.get("default", None)
        dest = self.kwargs.get("dest", name)
        option_dict[dest] = value


class Option(Argument):

    def as_argparse(self, name, parser, subparser, prefix=""):
        if prefix:
            self.kwargs["dest"] = prefix + self.kwargs.get("dest", name)
        self.args = ("--%s" % name,) + self.args
        parser.add_argument(*self.args, **self.kwargs)


class SubCommand(Argument):

    def __init__(self, nested, *args, **kwargs):
        """
        Merge a nested configuration element into the
        driver config.

        :param nested: a nested class from which to pull config from
        :type nested: :class:`TaskDriverType`
        """
        super().__init__(*args, **kwargs)
        self.nested = nested

    def as_argparse(self, name, parser, subparser, prefix=""):
        if subparser is None:
            raise ValueError("No subparser specified")
        subcommand = subparser.add_parser(name, *self.args, **self.kwargs)
        prefix += "%s." % name
        self.nested._config_model.as_argparse(subcommand, subparser,
                                              prefix=prefix)

    def as_dict(self, name, option_dict):
        option_dict[name] = self.nested._config_model.as_dict()


class NestedConfig(SubCommand):

    def __init__(self, nested):
        super().__init__(nested)

    def as_argparse(self, name, parser, subparser, prefix=""):
        prefix += "%s." % name
        self.nested._config_model.as_argparse(parser, subparser, prefix=prefix)


class DriverConfig:
    """
    Driver configuration object, this can be used to produce
    a dict of configuration items or an argument parser
    with options for all configuration items.
    """

    def __init__(self):
        """
        Create the configuration from a list of options

        :param options: list of options
        :type options: list of :class:`Option`
        """
        self.options = {}

    def add_option(self, name, option):
        """
        Add a new option to the configuration.
        The options actually performs the add
        operation so that we can have options that
        behave differently without changing the DriverConfig.

        :param option: the option to be added
        :type option: :class:`Option`
        """
        option.set_config(self.options, name)

    def update(self, other):
        """
        Merge another configuration in this one.
        The keys of the merged conf object are
        shadowed by the ones in this conf object.
        """
        merge_opts = dict(other.options)
        merge_opts.update(self.options)
        self.options = merge_opts

    def as_argparse(self, parser, subparser, prefix=""):
        """
        Attach the options to an argument parser

        :param parser: the argument parser
        :type parser: :class:`argparse.ArgumentParser`
        """
        for k,opt in self.options.items():
            opt.as_argparse(k, parser, subparser, prefix)

    def as_dict(self):
        """
        Create configuration dictionary with initialized options

        :return: dict mapping argname->default_value
        """
        args = {}
        for k,opt in self.options.items():
            opt.as_dict(k, args)
        return args


class TaskDriverType(type):
    """
    Type of the TaskDriver.
    Initialize the declarative component configuration into
    an instance attribute where the configuration options will be resolved.
    """

    def __new__(cls, name, bases, attrs, **kwargs):
        config = DriverConfig()
        for k,v in list(attrs.items()):
            if isinstance(v, Argument):
                del attrs[k]
                config.add_option(k, v)
        for base in bases:
            config.update(base._config_model)
        new_instance = super().__new__(cls, name, bases, attrs, **kwargs)
        new_instance._config_model = config
        return new_instance


class TaskDriver(metaclass=TaskDriverType):
    """
    Base interface of configurable components of a task driver.
    The driver components abstract the configuration options of
    tasks allowing to specify options in a single place.
    The task driver is the base class for plots
    and tools that use the cheriplot parsers, datasets
    and plotting tools.

    Configs are used to parametrize all elements (parser, transforms etc)
    they are merged by the init of the driver and by the task metaclass to
    generate the argparse tool options if needed. The argparse object is
    propagated back in the config to the inits of all the components, so
    we should have a TaskComponent class for that and ComponentConfig
    """
    @classmethod
    def make_config(cls, parser=None, subparser=None):
        """
        Setup a new configuration, if the parser is given, the
        configuration arguments will be created there,
        otherwise a dictionary of arguments with default values is
        returned.

        :param parser: an argument parser
        :type parser: :class:`argparse.ArgumentParser`
        """
        if parser != None:
            cls._config_model.as_argparse(parser, subparser)
        return cls._config_model.as_dict()

    def __init__(self, config):
        self._config = config
