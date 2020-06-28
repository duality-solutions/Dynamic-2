// Copyright (c) 2016-2019 Duality Blockchain Solutions Developers
// Copyright (c) 2014-2019 The Dash Core Developers
// Copyright (c) 2009-2019 The Bitcoin Developers
// Copyright (c) 2009-2019 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_QT_OVERVIEWPAGE_H
#define DYNAMIC_QT_OVERVIEWPAGE_H

#include "amount.h"

#include <memory>

#include <QMenu>
#include <QSortFilterProxyModel>
#include <QWidget>

class AssetFilterProxy;
class AssetViewDelegate;
class ClientModel;
class PlatformStyle;
class TransactionFilterProxy;
class TxViewDelegate;
class WalletModel;

namespace Ui
{
class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle* platformStyle, QWidget* parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void showOutOfSyncWarning(bool fShow);
    void showAssets();

public Q_SLOTS:
    void privateSendStatus();
    void setBalance(const CAmount& balance, const CAmount& total, const CAmount& stake, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, const CAmount& anonymizedBalance, const CAmount& watchOnlyBalance, const CAmount& watchOnlyStake, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void hideOrphans(bool fHide);

Q_SIGNALS:
    void transactionClicked(const QModelIndex& index);
    void assetSendClicked(const QModelIndex &index);
    void assetIssueSubClicked(const QModelIndex &index);
    void assetIssueUniqueClicked(const QModelIndex &index);
    void assetReissueClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();

private:
    QTimer* timer;
    Ui::OverviewPage* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    CAmount currentBalance;
    CAmount currentTotal;
    CAmount currentStake;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentAnonymizedBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    CAmount currentWatchOnlyStake;

    int nDisplayUnit;
    bool fShowAdvancedPSUI;

    TxViewDelegate* txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;
    std::unique_ptr<AssetFilterProxy> assetFilter;

    AssetViewDelegate *assetdelegate;
    QMenu *contextMenu;
    QAction *sendAction;
    QAction *issueSub;
    QAction *issueUnique;
    QAction *reissue;

    void SetupTransactionList(int nNumItems);
    void DisablePrivateSendCompletely();

private Q_SLOTS:
    void togglePrivateSend();
    void privateSendAuto();
    void privateSendReset();
    void privateSendInfo();
    void updateDisplayUnit();
    void updatePrivateSendProgress();
    void updateAdvancedPSUI(bool fShowAdvancedPSUI);
    void handleTransactionClicked(const QModelIndex& index);
    void handleAssetClicked(const QModelIndex &index);
    void updateAlerts(const QString& warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void assetSearchChanged();
};

#endif // DYNAMIC_QT_OVERVIEWPAGE_H
