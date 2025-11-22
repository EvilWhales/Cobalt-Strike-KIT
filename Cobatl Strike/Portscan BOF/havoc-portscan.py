#!/usr/bin/env python
# -*- coding: utf-8 -*-

from havoc import Demon, RegisterCommand, RegisterModule
import os

def portscanner( demonID, *param ):
    TaskID : str = None

    demon : Demon = None
    demon = Demon(demonID)

    if len(param) != 2: 
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid number of arguments" )
        return
    
    p = Packer()
    p.addstr(param[0]) # targets
    p.addstr(param[1]) # ports

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Running port scan" )
    demon.InlineExecute( TaskID, "go", "bin/portscanner.bof.o", p.getbuffer(), True)

    return TaskID

def pingscanner( demonID, *param ):
    TaskID : str = None

    demon : Demon = None
    demon = Demon(demonID)
    
    if len(param) != 1: 
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid number of arguments" )
        return

    p = Packer()
    p.addstr(param[0])

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Running ping scan" )
    demon.InlineExecute( TaskID, "go", "bin/pingscanner.bof.o", p.getbuffer(), True)

    return TaskID

RegisterCommand( pingscanner, "", "pingscan", "Ping targets (ICMP echo)", 0, "[targets]", "" )
RegisterCommand( portscanner, "", "portscan", "Port Scan targets and ports (TCP CONNECT)", 0, "[targets] [ports]", "" )

