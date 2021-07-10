// Copyright (c) 2016-2021 Duality Blockchain Solutions Developers
// Copyright (c) 2014-2021 The Dash Core Developers
// Copyright (c) 2009-2021 The Bitcoin Developers
// Copyright (c) 2009-2021 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privatesendconfig.h"
#include "ui_privatesendconfig.h"

#include "dynamicunits.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include "privatesend-client.h"

#include <QKeyEvent>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>

PrivateSendConfig::PrivateSendConfig(QWidget* parent) : QDialog(parent),
                                                        ui(new Ui::PrivateSendConfig),
                                                        model(0)
{
    ui->setupUi(this);

    connect(ui->buttonBasic, SIGNAL(clicked()), this, SLOT(clickBasic()));
    connect(ui->buttonHigh, SIGNAL(clicked()), this, SLOT(clickHigh()));
    connect(ui->buttonMax, SIGNAL(clicked()), this, SLOT(clickMax()));
}

PrivateSendConfig::~PrivateSendConfig()
{
    delete ui;
}

void PrivateSendConfig::setModel(WalletModel* model)
{
    this->model = model;
}

void PrivateSendConfig::clickBasic()
{
    configure(true, MAX_PRIVATESEND_AMOUNT, 2);

    QString strAmount(DynamicUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), MAX_PRIVATESEND_AMOUNT * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to basic (%1 and 2 rounds). You can change this at any time by opening Dynamic's configuration screen.")
            .arg(strAmount));

    close();
}

void PrivateSendConfig::clickHigh()
{
    configure(true, MAX_PRIVATESEND_AMOUNT, 8);

    QString strAmount(DynamicUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), MAX_PRIVATESEND_AMOUNT * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to high (%1 and 8 rounds). You can change this at any time by opening Dynamic's configuration screen.")
            .arg(strAmount));

    close();
}

void PrivateSendConfig::clickMax()
{
    configure(true, MAX_PRIVATESEND_AMOUNT, 16);

    QString strAmount(DynamicUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), MAX_PRIVATESEND_AMOUNT * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to maximum (%1 and 16 rounds). You can change this at any time by opening Dynamic's configuration screen.")
            .arg(strAmount));

    close();
}

void PrivateSendConfig::configure(bool enabled, int coins, int rounds)
{
    QSettings settings;

    settings.setValue("nPrivateSendRounds", rounds);
    settings.setValue("nPrivateSendAmount", coins);

    privateSendClient.nPrivateSendRounds = rounds;
    privateSendClient.nPrivateSendAmount = coins;
}
